<?php

declare(strict_types=1);

namespace App\Leads;

use App\Tenancy\TenantScope;
use DomainException;
use InvalidArgumentException;
use PDO;
use PDOStatement;

/**
 * Read model for lead search/filter (LFR-DASH-002) and lead detail (LFR-DASH-003).
 *
 * These two requirements were previously satisfied only by the pipeline counts +
 * exceptions queues in App\Dashboard. They need a real, tenant-scoped query surface:
 *  - LFR-DASH-002: filter leads by date range, source, status, assignee, priority,
 *    category (AI-extracted) and delivery state.
 *  - LFR-DASH-003: the lead detail view assembles the original submission, the AI
 *    output, the human field corrections, the interactions, the tasks and their
 *    delivery state, the audit trail, and the data-retention status for ONE lead.
 *
 * SECURITY (AC-001 / FR-TEN-002): every query is tenant-scoped through
 * App\Tenancy\TenantScope on the lead and on each joined table. The tenant predicate
 * is generated and bound by TenantScope - never interpolated, never caller-overridable.
 * The allowed filter fields are a fixed allowlist; an unknown field is refused, so a
 * caller cannot smuggle a raw SQL predicate.
 *
 * Filter dimensions map ONLY to columns that actually exist in the schema
 * (migrations/005_leads.sql, 006_lead_messaging.sql, 002_authz_audit.sql):
 *  - date       -> leads.created_at BETWEEN :from AND :to
 *  - source     -> leads.source = :source
 *  - status     -> leads.status = :status
 *  - assignee   -> lead_tasks.assigned_to = :assignee (joined, nullable)
 *  - priority   -> leads.priority = :priority            (added by migration 021)
 *  - category   -> lead_ai_analyses.analysis_json->>'$.category' = :category (joined)
 *  - delivery   -> EXISTS delivery with status = :delivery (correlated subquery)
 *
 * © AI WebScapes 2026
 */
final class LeadDashboard
{
    /**
     * The only filter dimensions a caller may request. Anything outside this list is
     * refused (deny-by-default on the filter surface).
     *
     * @var list<string>
     */
    private const ALLOWED_FILTERS = [
        'date',
        'source',
        'status',
        'assignee',
        'priority',
        'category',
        'delivery',
    ];

    private const VALID_PRIORITY = ['low', 'normal', 'high'];
    private const VALID_DELIVERY = ['pending', 'sent', 'failed'];

    public function __construct(private PDO $pdo, private int $tenantId)
    {
        // Mirror DashboardRepository: a dashboard reader cannot be built for a
        // null/zero/negative tenant, so every read it performs is already bound.
        new TenantScope($tenantId);
    }

    /**
     * LFR-DASH-002 - filter leads by the requested dimensions.
     *
     * @param array<string, mixed> $filters subset of ALLOWED_FILTERS keys.
     *
     * @return list<array<string, mixed>> one row per lead matching every supplied filter.
     */
    public function filterLeads(array $filters): array
    {
        $normalized = $this->normalizeFilters($filters);

        $scope = new TenantScope($this->tenantId);
        $sql = 'SELECT DISTINCT l.id, l.tenant_id, l.email, l.name, l.source, l.status, l.priority,'
            . ' l.created_at FROM leads l';
        $params = [];

        if (isset($normalized['assignee'])) {
            $sql .= ' LEFT JOIN lead_tasks t ON t.lead_id = l.id AND t.tenant_id = l.tenant_id';
        }
        if (isset($normalized['category'])) {
            $sql .= ' LEFT JOIN lead_ai_analyses a ON a.lead_id = l.id AND a.tenant_id = l.tenant_id';
        }
        if (isset($normalized['delivery'])) {
            $sql .= ' LEFT JOIN message_deliveries m ON m.lead_id = l.id AND m.tenant_id = l.tenant_id';
        }

        // Qualify tenant_id: the WHERE joins other tenant-scoped tables, so a bare
        // predicate is ambiguous. TenantScope generates the value; we bind it below.
        $sql .= ' WHERE l.' . TenantScope::COLUMN . ' = :' . TenantScope::PARAM;

        if (isset($normalized['date'])) {
            $sql .= ' AND l.created_at BETWEEN :from AND :to';
            $params['from'] = $normalized['date']['from'];
            $params['to'] = $normalized['date']['to'];
        }
        if (isset($normalized['source'])) {
            $sql .= ' AND l.source = :source';
            $params['source'] = $normalized['source'];
        }
        if (isset($normalized['status'])) {
            $sql .= ' AND l.status = :status';
            $params['status'] = $normalized['status'];
        }
        if (isset($normalized['assignee'])) {
            $sql .= ' AND t.assigned_to = :assignee';
            $params['assignee'] = $normalized['assignee'];
        }
        if (isset($normalized['priority'])) {
            $sql .= ' AND l.priority = :priority';
            $params['priority'] = $normalized['priority'];
        }
        if (isset($normalized['category'])) {
            $sql .= " AND a.analysis_json->>'$.category' = :category";
            $params['category'] = $normalized['category'];
        }
        if (isset($normalized['delivery'])) {
            $sql .= ' AND m.status = :delivery';
            $params['delivery'] = $normalized['delivery'];
        }

        $sql .= ' ORDER BY l.created_at DESC, l.id DESC';

        $statement = $this->pdo->prepare($sql);
        $scope->bindTo($statement);
        foreach ($params as $key => $value) {
            $statement->bindValue($key, $value);
        }
        $statement->execute();

        return $this->rows($statement);
    }

    /**
     * LFR-DASH-003 - the lead detail view: original submission, AI output, corrections,
     * interactions, tasks (+ delivery state), audit history, and retention status.
     *
     * @return array<string, mixed>|null null when the lead does not belong to the tenant.
     */
    public function detail(int $leadId): ?array
    {
        $scope = new TenantScope($this->tenantId);
        $lead = $this->pdo->prepare(
            'SELECT id, tenant_id, email, name, company, source, status, priority, ip_hash, created_at'
            . ' FROM leads' . $scope->where('id = :lead')
        );
        $scope->bindTo($lead);
        $lead->bindValue('lead', $leadId, PDO::PARAM_INT);
        $lead->execute();
        $base = $lead->fetch(PDO::FETCH_ASSOC);
        if ($base === false) {
            return null; // not found OR not this tenant - same response (AC-001: no cross-tenant signal)
        }

        return [
            'lead' => $base,
            'original_submission' => $this->oneRow(
                'SELECT payload_json, ip_hash, user_agent, created_at FROM lead_submissions'
                . $scope->where('lead_id = :lead') . ' ORDER BY id DESC LIMIT 1',
                $leadId
            ),
            'ai_output' => $this->oneRow(
                'SELECT status, analysis_json, error_message, created_at FROM lead_ai_analyses'
                . $scope->where('lead_id = :lead') . ' ORDER BY id DESC LIMIT 1',
                $leadId
            ),
            'corrections' => $this->manyRows(
                'SELECT field_name, old_value, new_value, corrected_by, created_at FROM lead_field_corrections'
                . $scope->where('lead_id = :lead') . ' ORDER BY id ASC',
                $leadId
            ),
            'interactions' => $this->manyRows(
                'SELECT channel, direction, body, actor_id, occurred_at FROM lead_interactions'
                . $scope->where('lead_id = :lead') . ' ORDER BY id ASC',
                $leadId
            ),
            'tasks' => $this->tasksWithDelivery($leadId, $scope),
            'audit_history' => $this->manyRows(
                'SELECT event, outcome, object_type, object_id, detail, created_at FROM audit_log'
                . $scope->where("object_type = 'lead' AND object_id = :lead") . ' ORDER BY id ASC',
                $leadId,
                ['lead' => (string) $leadId]
            ),
            'data_retention_status' => $this->retentionStatus($leadId, $scope),
        ];
    }

    /**
     * @param array<string, mixed> $filters
     * @return array<string, mixed> normalized, validated filters.
     */
    private function normalizeFilters(array $filters): array
    {
        $out = [];
        foreach ($filters as $field => $value) {
            if (!in_array($field, self::ALLOWED_FILTERS, true)) {
                throw new DomainException(sprintf('Refusing unknown lead filter dimension "%s".', (string) $field));
            }
            $out[$field] = $this->validateFilterValue($field, $value);
        }

        return $out;
    }

    /**
     * @param mixed $value
     * @return mixed validated value (throws InvalidArgumentException on bad input).
     */
    private function validateFilterValue(string $field, mixed $value)
    {
        switch ($field) {
            case 'date':
                if (!is_array($value) || !isset($value['from'], $value['to'])) {
                    throw new InvalidArgumentException('date filter requires from + to timestamps.');
                }

                return ['from' => $value['from'], 'to' => $value['to']];

            case 'source':
            case 'status':
            case 'category':
                if (!is_string($value) || $value === '') {
                    throw new InvalidArgumentException(sprintf('%s filter requires a non-empty string.', $field));
                }

                return $value;

            case 'assignee':
                if (!is_int($value) || $value <= 0) {
                    throw new InvalidArgumentException('assignee filter requires a positive user id.');
                }

                return $value;

            case 'priority':
                if (!in_array($value, self::VALID_PRIORITY, true)) {
                    throw new InvalidArgumentException('priority must be one of low/normal/high.');
                }

                return $value;

            case 'delivery':
                if (!in_array($value, self::VALID_DELIVERY, true)) {
                    throw new InvalidArgumentException('delivery must be one of pending/sent/failed.');
                }

                return $value;

            default:
                throw new DomainException(sprintf('Refusing unknown lead filter dimension "%s".', $field));
        }
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function tasksWithDelivery(int $leadId, TenantScope $scope): array
    {
        $tasksStmt = $this->pdo->prepare(
            'SELECT id, title, status, due_at, assigned_to, created_at FROM lead_tasks'
            . $scope->where('lead_id = :lead') . ' ORDER BY id ASC'
        );
        $scope->bindTo($tasksStmt);
        $tasksStmt->bindValue('lead', $leadId, PDO::PARAM_INT);
        $tasksStmt->execute();
        $tasks = $this->rows($tasksStmt);

        foreach ($tasks as &$task) {
            $taskId = is_scalar($task['id'] ?? null) ? (int) $task['id'] : 0;
            $delivery = $this->pdo->prepare(
                'SELECT status FROM message_deliveries'
                . $scope->where('lead_id = :lead AND kind = :kind') . ' ORDER BY id DESC LIMIT 1'
            );
            $scope->bindTo($delivery);
            $delivery->bindValue('lead', $leadId, PDO::PARAM_INT);
            $delivery->bindValue('kind', 'task_' . $taskId);
            $delivery->execute();
            $row = $delivery->fetch(PDO::FETCH_ASSOC);
            $task['delivery_state'] = is_array($row) && isset($row['status']) ? $row['status'] : 'none';
        }
        unset($task);

        return $tasks;
    }

    /**
     * @return array<string, mixed>
     */
    private function retentionStatus(int $leadId, TenantScope $scope)
    {
        // A lead is retention-cleared when a verified deletion proof exists for this
        // tenant's 'lead' data class. The proof table is tenant + data_class scoped
        // (see src/Data/RetentionService.php), not per-object, so scope it directly.
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM data_deletion_verifications v'
            . ' WHERE v.' . TenantScope::COLUMN . ' = :' . TenantScope::PARAM
            . ' AND v.data_class = :class'
        );
        $scope->bindTo($stmt);
        $stmt->bindValue('class', 'lead');
        $stmt->execute();
        $cleared = (int) $stmt->fetchColumn() > 0;

        return ['retained' => !$cleared, 'cleared_by_retention' => $cleared];
    }

    /**
     * @param array<string, string> $extra
     * @return array<string, mixed>|null
     */
    private function oneRow(string $sql, int $leadId, array $extra = []): ?array
    {
        $scope = new TenantScope($this->tenantId);
        $statement = $this->pdo->prepare($sql);
        $scope->bindTo($statement);
        $statement->bindValue('lead', $leadId, PDO::PARAM_INT);
        foreach ($extra as $k => $v) {
            $statement->bindValue($k, $v);
        }
        $statement->execute();
        $row = $statement->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    /**
     * @param array<string, string> $extra
     * @return list<array<string, mixed>>
     */
    private function manyRows(string $sql, int $leadId, array $extra = []): array
    {
        $scope = new TenantScope($this->tenantId);
        $statement = $this->pdo->prepare($sql);
        $scope->bindTo($statement);
        $statement->bindValue('lead', $leadId, PDO::PARAM_INT);
        foreach ($extra as $k => $v) {
            $statement->bindValue($k, $v);
        }
        $statement->execute();

        return $this->rows($statement);
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function rows(PDOStatement $statement): array
    {
        $fetched = $statement->fetchAll(PDO::FETCH_ASSOC);
        $rows = [];
        foreach ($fetched as $row) {
            if (!is_array($row)) {
                throw new \UnexpectedValueException('Unexpected non-array row from lead dashboard query.');
            }
            $rows[] = $row;
        }

        return $rows;
    }
}
