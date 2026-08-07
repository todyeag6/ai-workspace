<?php

declare(strict_types=1);

namespace App\Assessment;

use App\Tenancy\TenantScope;
use InvalidArgumentException;
use JsonException;
use PDO;

/**
 * Business-AI Assessment Framework (BAAF-001..006) + assessment scoring and
 * reporting (FR-ASMT-001/002).
 *
 * FAIL-CLOSED DECISIONING. The BAAF gates are enforced in code and a missing or
 * malformed input can NEVER produce a 'go'. Every gate is reflexive: a high
 * composite score does not lift a prohibited-risk or ownerless defect (BAAF §3).
 * The decision is computed here and only the resulting record is persisted; the
 * stored row is never trusted as the authority for the gate.
 *
 * © AI WebScapes 2026
 */
final class AssessmentService
{
    /** BAAF Table 2 weights (verified). Risk is inverted: higher raw risk lowers score. */
    private const WEIGHTS = [
        'business_value' => 0.25,
        'feasibility'    => 0.20,
        'risk'           => 0.20,
        'adoption'       => 0.15,
        'maintainability' => 0.10,
        'time_to_value'  => 0.10,
    ];

    public const SCHEMA_VERSION = '1.0';

    public function __construct(private PDO $pdo)
    {
    }

    /**
     * FR-ASMT-001 — weighted composite equals BAAF Table 2.
     * composite = Σ w_i · x_i, with risk inverted as (1 − risk).
     *
     * @param  array<string,float> $scores Keys exactly match self::WEIGHTS.
     * @throws InvalidArgumentException When a required dimension is missing.
     */
    public function score(array $scores): float
    {
        $composite = 0.0;
        foreach (self::WEIGHTS as $key => $weight) {
            if (!array_key_exists($key, $scores)) {
                throw new InvalidArgumentException(sprintf('Missing assessment dimension "%s".', $key));
            }
            $value = (float) $scores[$key];
            $weighted = $key === 'risk' ? (1.0 - $value) : $value;
            $composite += $weight * $weighted;
        }

        return round($composite, 4);
    }

    /**
     * BAAF-003/004/005/006 + §3 — evaluate a use case and return its disposition.
     * Order is load-bearing: prohibited-risk is checked FIRST and cannot be
     * rescued by a high score.
     *
     * @param  array<string,mixed> $input
     * @throws ProhibitedRiskException  BAAF-004 / §3.
     * @throws ProcessDefectException    BAAF-003 / BAAF-006.
     */
    public function decide(array $input): Decision
    {
        $consequence = $input['consequence'] ?? 'low';
        $validation  = $input['validation'] ?? 'inadequate';
        $owner       = $input['process_owner'] ?? null;
        $certainty   = $input['benefit_certainty'] ?? 'uncertain';

        // BAAF-004 + §3: high consequence + inadequate validation is prohibited.
        // The 'score' key (if present) is intentionally NOT consulted here — a
        // high score must never override this gate.
        if ($consequence === 'high' && $validation === 'inadequate') {
            throw new ProhibitedRiskException(
                'BAAF-004: autonomous execution prohibited when consequences are '
                . 'high and validation/reversal is inadequate.'
            );
        }

        // BAAF-003: never automate an ownerless process.
        if ($owner === null || $owner === '' || $owner === false) {
            throw new ProcessDefectException('BAAF-003: process has no defined owner.');
        }

        // BAAF-005: uncertainty in data quality / adoption / model / integration
        // / benefit requires a pilot rather than a go. This short-circuits
        // BEFORE the BAAF-006 production-safeguard check, because a pilot case
        // may not yet carry production no-go criteria / a permanent fallback.
        if ($certainty === 'uncertain') {
            return new Decision('pilot', 'BAAF-005: benefit or readiness uncertain — pilot required.');
        }

        // BAAF-006: every PRODUCTION (go) use case requires explicit no-go
        // criteria and a safe fallback. Reached only for certain, non-pilot cases.
        $noGo     = $input['no_go_criteria'] ?? null;
        $fallback = $input['safe_fallback'] ?? null;
        if ($noGo === null || $noGo === '' || $fallback === null || $fallback === '') {
            throw new ProcessDefectException(
                'BAAF-006: production use case missing explicit no-go criteria or safe fallback.'
            );
        }

        return new Decision('go', 'BAAF gates satisfied.');
    }

    /**
     * FR-ASMT-002 — build a VERSIONED report with assumptions, deployment
     * alternatives, risk classification, expected value, and next actions.
     *
     * @param  array<string,mixed> $spec
     * @return array<string,mixed>
     * @throws InvalidArgumentException When required report fields are absent.
     */
    public function generateReport(array $spec): array
    {
        foreach (['assumptions', 'alternatives', 'expected_value', 'next_actions'] as $required) {
            if (!array_key_exists($required, $spec)) {
                throw new InvalidArgumentException(sprintf('Report missing required field "%s".', $required));
            }
        }

        $scores = $spec['scores'] ?? [];
        $composite = $scores !== [] ? $this->score($scores) : 0.0;

        return [
            'schema_version'       => self::SCHEMA_VERSION,
            'title'                => $spec['title'] ?? '',
            'composite_score'      => $composite,
            'risk_classification'  => $this->classifyRisk($spec['consequence'] ?? 'low'),
            'assumptions'          => $spec['assumptions'],
            'alternatives'         => $spec['alternatives'],
            'expected_value'       => $spec['expected_value'],
            'next_actions'         => $spec['next_actions'],
        ];
    }

    private function classifyRisk(string $consequence): string
    {
        return match ($consequence) {
            'high'   => 'high',
            'medium' => 'medium',
            default  => 'low',
        };
    }

    /**
     * Persist an assessment record (tenant-scoped). Returns the new id.
     *
     * @param  array<string,mixed>|null $report
     * @throws JsonException
     */
    public function record(
        int $tenantId,
        string $title,
        string $disposition,
        float $compositeScore,
        ?array $report = null
    ): int {
        $scope = new TenantScope($tenantId);
        $sql = 'INSERT INTO assessments (tenant_id, title, disposition, composite_score, report_json, schema_version) '
            . 'VALUES (:' . TenantScope::PARAM . ', :title, :disposition, :score, :report, :schema)';
        $statement = $this->pdo->prepare($sql);
        $scope->bindTo($statement);
        $statement->bindValue('title', $title);
        $statement->bindValue('disposition', $disposition);
        $statement->bindValue('score', $compositeScore);
        $statement->bindValue('report', $report === null ? null : json_encode($report, JSON_THROW_ON_ERROR));
        $statement->bindValue('schema', self::SCHEMA_VERSION);
        $statement->execute();

        $id = $this->pdo->lastInsertId();

        return is_string($id) ? (int) $id : 0;
    }

    /**
     * Retrieve a tenant's assessment by id. A tenant can ONLY read its own
     * record (AC-001); a cross-tenant lookup returns null, never the row.
     *
     * @return array<string,mixed>|null
     * @throws JsonException
     */
    public function get(int $tenantId, int $id): ?array
    {
        $scope = new TenantScope($tenantId);
        $statement = $this->pdo->prepare(
            'SELECT id, tenant_id, title, disposition, composite_score, report_json, schema_version, created_at '
            . 'FROM assessments WHERE id = :id AND ' . TenantScope::COLUMN . ' = :' . TenantScope::PARAM
        );
        $statement->bindValue('id', $id, PDO::PARAM_INT);
        $scope->bindTo($statement);
        $statement->execute();

        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            return null;
        }

        if ($row['report_json'] !== null) {
            $row['report_json'] = json_decode($row['report_json'], true, 512, JSON_THROW_ON_ERROR);
        }

        return $row;
    }
}
