<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Audit\AuditLogger;
use App\Data\TenantRepository;
use DateTimeImmutable;
use DateTimeZone;
use JsonException;
use PDO;
use RuntimeException;

/**
 * Tenant-scoped persistence for security findings (SFR-FIND-001,
 * SFR-FIND-002, SFR-AI-001, SFR-AUD-001).
 *
 * THE ONE THING THIS CLASS EXISTS TO GUARANTEE
 * ---------------------------------------------
 * SFR-FIND-002: repeated evidence updates occurrence history WITHOUT
 * destroying previous state. record() therefore has exactly two paths and no
 * third:
 *   - the fingerprint is NEW  -> insert one finding, append one occurrence
 *   - the fingerprint is KNOWN -> append one occurrence, and touch ONLY the
 *                                 derived history fields (last_seen_at,
 *                                 occurrence_count, widened affected_assets)
 * A repeat sighting never rewrites the title, severity, confidence,
 * remediation, owner or status. That is the load-bearing distinction: being
 * seen again is an OBSERVATION, and reviewing a finding is a DECISION. A scan
 * that re-observed a risk-accepted issue must not quietly reopen it, and one
 * that re-observed a confirmed critical must not silently downgrade it back to
 * the machine's suggestion. The database backs the same guarantee with a
 * UNIQUE (tenant_id, fingerprint) key, so even a caller that bypassed record()
 * could not create the duplicate.
 *
 * SFR-AI-001 IS ENFORCED BY SIGNATURE, NOT BY TRUST
 * --------------------------------------------------
 * "AI may summarize and suggest severity/remediation but shall not alter
 * confirmed status, close findings, or authorize risk acceptance without human
 * decision." Two mechanisms:
 *   1. attachAiSuggestion() is the ONLY method an AI-driven caller needs, and
 *      it writes only ai_suggested_severity / ai_suggested_remediation /
 *      ai_summary. There is no argument it accepts that could change status,
 *      severity, confidence or remediation.
 *   2. Every transition into a human-only status (confirmed, false_positive,
 *      risk_accepted, remediated, closed - Finding::HUMAN_ONLY_STATUSES)
 *      REQUIRES a non-empty human identifier and throws HumanDecisionRequired
 *      without one. Fail closed, and audited afterwards (SFR-AUD-001), so a
 *      disposition always has a named owner in the trail.
 *
 * WHY THE AUDIT WRITE COMES AFTER THE DATABASE WRITE. Same ordering as
 * ScanProfileRepository::approveDestructiveChecks(): validate, then write, then
 * evidence. The trail never claims a decision the database refused.
 *
 * AC-001 comes from the base class: construction builds a TenantScope, and
 * every statement carries `tenant_id = :tenant` bound internally.
 *
 * © AI WebScapes 2026
 */
final class FindingRepository extends TenantRepository
{
    public const AUDIT_CONFIRM = 'secfinding.status.confirm';
    public const AUDIT_STATUS = 'secfinding.status.change';
    public const AUDIT_SEVERITY = 'secfinding.severity.revise';
    public const AUDIT_ASSIGN = 'secfinding.owner.assign';
    public const AUDIT_AI_SUGGESTION = 'secfinding.ai.suggestion';

    private const AUDIT_SOURCE = 'finding_repository';

    private const AUDIT_OBJECT_TYPE = 'security_finding';

    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    private FindingOccurrenceRepository $occurrences;

    private FindingEngine $engine;

    private ?AuditLogger $audit;

    /**
     * @param AuditLogger|null $audit Required by every human-decision path,
     *                                which refuses to run unevidenced
     *                                (SFR-AUD-001).
     */
    public function __construct(
        PDO $pdo,
        ?int $tenantId,
        ?AuditLogger $audit = null,
        ?FindingEngine $engine = null
    ) {
        parent::__construct($pdo, $tenantId);

        // Built here rather than injected so a caller cannot hand in an
        // occurrence repository scoped to a different tenant.
        $this->occurrences = new FindingOccurrenceRepository($pdo, $tenantId);
        $this->engine = $engine ?? new FindingEngine();
        $this->audit = $audit;
    }

    protected function table(): string
    {
        return 'security_findings';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'fingerprint',
            'title',
            'category',
            'severity',
            'confidence',
            'affected_assets',
            'remediation',
            'standards_mapping',
            'owner',
            'status',
            'sla_due_at',
            'first_seen_at',
            'last_seen_at',
            'occurrence_count',
            'ai_suggested_severity',
            'ai_suggested_remediation',
            'ai_summary',
            'confirmed_by',
            'confirmed_at',
            'closed_by',
            'closed_at',
            'created_at',
        ];
    }

    /**
     * Records one observation of an issue: creates the finding on first sight,
     * appends an occurrence every time (SFR-FIND-001, SFR-FIND-002).
     *
     * Returns the STABLE finding id in both cases - the caller does not need
     * to know, and must not care, whether this sighting was the first.
     *
     * @param array<string, mixed> $signature  What was observed, structurally.
     *                                         Fingerprinted, so it must not
     *                                         carry run-specific values.
     */
    public function record(
        string $title,
        string $category,
        string $canonicalAsset,
        array $signature,
        string $baseSeverity,
        string $confidence,
        int $scanId,
        ?int $assetId = null,
        ?int $evidenceId = null,
        ?string $evidenceHash = null,
        ?DateTimeImmutable $observedAt = null,
        ?string $note = null
    ): int {
        $moment = $observedAt ?? $this->clock();

        $decision = $this->engine->classify(
            $title,
            $category,
            $canonicalAsset,
            $signature,
            $baseSeverity,
            $confidence,
            $moment
        );

        $existing = $this->findByFingerprint($decision['fingerprint']);

        if ($existing === null) {
            $findingId = $this->insertNew($decision, $assetId, $moment);
            $status = Finding::STATUS_OPEN;
        } else {
            $findingId = $existing->id();
            $this->touchHistory($existing, $moment, $assetId);
            // The occurrence records the disposition AS IT WAS when the
            // sighting landed - not what a fresh classification would say.
            $status = $existing->status();
        }

        $this->occurrences->add(
            $findingId,
            $scanId,
            $moment,
            $status,
            $assetId,
            $evidenceId,
            $evidenceHash,
            $note
        );

        return $findingId;
    }

    /**
     * Attaches the AI's ADVISORY opinion (SFR-AI-001).
     *
     * Look at what this method cannot express: there is no status argument, no
     * authoritative severity argument, no owner argument. An AI-driven caller
     * holding this repository has no way to alter a decision - not because it
     * is asked not to, but because the method to do it does not exist on the
     * path it uses. BRD section 5's "automated severity is advisory until
     * validated" is therefore structural here.
     */
    public function attachAiSuggestion(
        int $id,
        ?string $suggestedSeverity = null,
        ?string $suggestedRemediation = null,
        ?string $summary = null
    ): void {
        $finding = $this->requireById($id);

        // Runs the value object's own allowlist check before any write.
        $updated = $finding->withAiSuggestion($suggestedSeverity, $suggestedRemediation, $summary);

        $this->updateScoped(
            [
                'ai_suggested_severity' => $updated->aiSuggestedSeverity(),
                'ai_suggested_remediation' => $updated->aiSuggestedRemediation(),
                'ai_summary' => $updated->aiSummary(),
            ],
            'id = :id',
            ['id' => $id]
        );

        // Audited as an AI action with no actor user id: the trail shows a
        // machine suggestion, distinct from a human decision (SFR-AUD-001).
        $this->requireAudit()->record(
            $this->tenantId(),
            null,
            self::AUDIT_AI_SUGGESTION,
            self::AUDIT_OBJECT_TYPE,
            (string) $id,
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            'ai suggestion attached to finding ' . $id
        );
    }

    /**
     * Moves a finding into a status that SFR-AI-001 reserves for a human.
     *
     * @param string $decidedBy The human who made the call. Empty is refused.
     *
     * @throws HumanDecisionRequired When a human-only status is reached without
     *         a named human - the fail-closed path.
     */
    public function transitionStatus(
        int $id,
        string $status,
        string $decidedBy,
        ?int $actorUserId = null,
        ?DateTimeImmutable $decidedAt = null,
        string $reason = ''
    ): void {
        if (!in_array($status, Finding::STATUSES, true)) {
            throw new RuntimeException(sprintf(
                'Unknown finding status "%s". It must be one of: %s (allowlist, AC-002).',
                $status,
                implode(', ', Finding::STATUSES)
            ));
        }

        $human = trim($decidedBy);

        if (in_array($status, Finding::HUMAN_ONLY_STATUSES, true) && $human === '') {
            // Fail closed. SFR-AI-001: confirming, closing and accepting risk
            // are human decisions, and a decision with no decider is not one.
            throw new HumanDecisionRequired(
                $status,
                sprintf(
                    'Moving a finding to "%s" requires a named human decision; no AI or automated '
                    . 'caller may make it (SFR-AI-001).',
                    $status
                )
            );
        }

        // SBR-5.2: a false-positive disposition requires a reason AND a
        // reviewer. The reviewer is $decidedBy, checked above; the reason is
        // checked here rather than left optional, because "not a real finding"
        // with no stated why is exactly the disposition that hides mistakes.
        if ($status === Finding::STATUS_FALSE_POSITIVE && trim($reason) === '') {
            throw new RuntimeException(
                'A false-positive disposition requires a stated reason and a reviewer (SBR-5.2).'
            );
        }

        $this->requireById($id);
        $moment = $decidedAt ?? $this->clock();
        $stamp = $moment->format(self::TIMESTAMP_FORMAT);

        $values = ['status' => $status];

        if ($status === Finding::STATUS_CONFIRMED) {
            $values['confirmed_by'] = $human;
            $values['confirmed_at'] = $stamp;
        }

        if (in_array($status, [Finding::STATUS_CLOSED, Finding::STATUS_REMEDIATED], true)) {
            $values['closed_by'] = $human;
            $values['closed_at'] = $stamp;
        }

        $this->updateScoped($values, 'id = :id', ['id' => $id]);

        $this->requireAudit()->record(
            $this->tenantId(),
            $actorUserId,
            $status === Finding::STATUS_CONFIRMED ? self::AUDIT_CONFIRM : self::AUDIT_STATUS,
            self::AUDIT_OBJECT_TYPE,
            (string) $id,
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf('finding %d -> %s by %s%s', $id, $status, $human, $reason === '' ? '' : ': ' . $reason)
        );
    }

    /**
     * A human revising the authoritative severity (BRD section 5: automated
     * severity is advisory UNTIL VALIDATED - this is the validation).
     *
     * The SLA is recomputed from the FIRST sighting, not from now: re-rating a
     * month-old finding as critical does not grant it a fresh 24 hours.
     *
     * @throws HumanDecisionRequired When no human is named.
     */
    public function reviseSeverity(
        int $id,
        string $severity,
        string $decidedBy,
        ?int $actorUserId = null
    ): void {
        $human = trim($decidedBy);
        if ($human === '') {
            throw new HumanDecisionRequired(
                $severity,
                'Revising the authoritative severity is a human decision; automated severity is '
                . 'advisory only (SFR-AI-001, BRD section 5).'
            );
        }

        if (!in_array($severity, Finding::SEVERITIES, true)) {
            throw new RuntimeException(sprintf(
                'Unknown severity "%s". It must be one of: %s (allowlist, AC-002).',
                $severity,
                implode(', ', Finding::SEVERITIES)
            ));
        }

        $finding = $this->requireById($id);
        $due = $this->engine->slaDueAt($severity, $finding->firstSeenAt());

        $this->updateScoped(
            [
                'severity' => $severity,
                'sla_due_at' => $due?->format(self::TIMESTAMP_FORMAT),
            ],
            'id = :id',
            ['id' => $id]
        );

        $this->requireAudit()->record(
            $this->tenantId(),
            $actorUserId,
            self::AUDIT_SEVERITY,
            self::AUDIT_OBJECT_TYPE,
            (string) $id,
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf('finding %d severity %s -> %s by %s', $id, $finding->severity(), $severity, $human)
        );
    }

    /**
     * Assigns the owner accountable for remediation (SFR-FIND-001 "owner",
     * FRD section 2 "assign owner and SLA"). Audited under SFR-AUD-001, which
     * names assignment explicitly.
     */
    public function assignOwner(int $id, string $owner, ?int $actorUserId = null): void
    {
        $assignee = trim($owner);
        if ($assignee === '') {
            throw new RuntimeException('An owner assignment must name someone (SFR-FIND-001).');
        }

        $this->requireById($id);

        $this->updateScoped(['owner' => $assignee], 'id = :id', ['id' => $id]);

        $this->requireAudit()->record(
            $this->tenantId(),
            $actorUserId,
            self::AUDIT_ASSIGN,
            self::AUDIT_OBJECT_TYPE,
            (string) $id,
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf('finding %d assigned to %s', $id, $assignee)
        );
    }

    /**
     * Records the human-owned remediation guidance. Separate from the AI's
     * suggested remediation, which never lands here (SFR-AI-001).
     */
    public function setRemediation(int $id, string $remediation): void
    {
        $this->requireById($id);

        $text = trim($remediation);
        $this->updateScoped(
            ['remediation' => $text === '' ? null : $text],
            'id = :id',
            ['id' => $id]
        );
    }

    /**
     * Null both when the finding does not exist and when it belongs to another
     * tenant - deliberately indistinguishable (AC-001).
     */
    public function findById(int $id): ?Finding
    {
        $rows = $this->selectScoped('id = :id', ['id' => $id]);
        if ($rows === []) {
            return null;
        }

        return Finding::fromRow($rows[0]);
    }

    /**
     * The deduplication lookup (SFR-FIND-002). Null when this tenant has never
     * seen the issue.
     */
    public function findByFingerprint(string $fingerprint): ?Finding
    {
        $hash = trim($fingerprint);
        if ($hash === '') {
            throw new RuntimeException('A fingerprint lookup needs a non-empty fingerprint.');
        }

        $rows = $this->selectScoped('fingerprint = :fingerprint', ['fingerprint' => $hash]);
        if ($rows === []) {
            return null;
        }

        return Finding::fromRow($rows[0]);
    }

    /**
     * @throws RuntimeException When no such finding exists in this tenant.
     */
    public function requireById(int $id): Finding
    {
        $finding = $this->findById($id);
        if ($finding === null) {
            throw new RuntimeException(sprintf(
                'Finding %d does not exist for tenant %d.',
                $id,
                $this->tenantId()
            ));
        }

        return $finding;
    }

    /**
     * The full sighting history of one finding, oldest first (SFR-FIND-002).
     *
     * @return list<FindingOccurrence>
     */
    public function occurrencesFor(int $findingId): array
    {
        if ($this->findById($findingId) === null) {
            // Not visible in this tenant: no history is disclosed (AC-001).
            return [];
        }

        return $this->occurrences->forFinding($findingId);
    }

    /**
     * Every finding in one status - the sanctioned read for a report that must
     * distinguish confirmed / accepted / remediated items (SFR-REPORT-001).
     *
     * @return list<Finding>
     */
    public function findByStatus(string $status): array
    {
        $rows = $this->selectScoped('status = :status', ['status' => $status]);

        $findings = [];
        foreach ($rows as $row) {
            $findings[] = Finding::fromRow($row);
        }

        usort($findings, static fn (Finding $a, Finding $b): int => $a->id() <=> $b->id());

        return $findings;
    }

    /**
     * Findings whose remediation deadline has passed (SBR-5.1).
     *
     * @return list<Finding>
     */
    public function overdue(?DateTimeImmutable $now = null): array
    {
        $moment = $now ?? $this->clock();

        $rows = $this->selectScoped(
            'sla_due_at IS NOT NULL AND sla_due_at < :now',
            ['now' => $moment->format(self::TIMESTAMP_FORMAT)]
        );

        $findings = [];
        foreach ($rows as $row) {
            $finding = Finding::fromRow($row);
            // An already-closed finding is not chasing a deadline.
            if (in_array($finding->status(), [Finding::STATUS_CLOSED, Finding::STATUS_REMEDIATED], true)) {
                continue;
            }

            $findings[] = $finding;
        }

        usort($findings, static fn (Finding $a, Finding $b): int => $a->id() <=> $b->id());

        return $findings;
    }

    /**
     * Creates the finding on first sight. Born `open` and never `confirmed`:
     * nothing is validated by having been observed once (SFR-AI-001).
     *
     * @param array{
     *     fingerprint: string,
     *     title: string,
     *     category: string,
     *     severity: string,
     *     confidence: string,
     *     standards_mapping: list<string>,
     *     sla_due_at: DateTimeImmutable|null,
     *     ai_suggested_severity: string,
     *     requires_alert: bool
     * } $decision
     */
    private function insertNew(array $decision, ?int $assetId, DateTimeImmutable $moment): int
    {
        $stamp = $moment->format(self::TIMESTAMP_FORMAT);

        return (int) $this->insertScoped([
            'fingerprint' => $decision['fingerprint'],
            'title' => $decision['title'],
            'category' => $decision['category'],
            'severity' => $decision['severity'],
            'confidence' => $decision['confidence'],
            'affected_assets' => $this->encodeList($assetId === null ? [] : [$assetId]),
            'remediation' => null,
            'standards_mapping' => $this->encodeList($decision['standards_mapping']),
            'owner' => '',
            'status' => Finding::STATUS_OPEN,
            'sla_due_at' => $decision['sla_due_at']?->format(self::TIMESTAMP_FORMAT),
            'first_seen_at' => $stamp,
            'last_seen_at' => $stamp,
            'occurrence_count' => 1,
            // The provenance of the number stays visible: the same value is
            // recorded as the machine's suggestion (BRD section 5).
            'ai_suggested_severity' => $decision['ai_suggested_severity'],
        ]);
    }

    /**
     * Updates ONLY the derived history of an existing finding (SFR-FIND-002).
     *
     * The set of columns written here is the whole guarantee: last_seen_at,
     * occurrence_count and a widened affected_assets. Title, severity,
     * confidence, remediation, owner and status are absent on purpose - a
     * re-observation is not a review, and must not overwrite a human's
     * disposition.
     */
    private function touchHistory(Finding $existing, DateTimeImmutable $moment, ?int $assetId): void
    {
        $updated = $existing->withOccurrence($moment, $assetId === null ? [] : [$assetId]);

        $this->updateScoped(
            [
                'last_seen_at' => $updated->lastSeenAt()->format(self::TIMESTAMP_FORMAT),
                'occurrence_count' => $updated->occurrenceCount(),
                'affected_assets' => $this->encodeList($updated->affectedAssets()),
            ],
            'id = :id',
            ['id' => $existing->id()]
        );
    }

    /**
     * @param list<int>|list<string> $values
     */
    private function encodeList(array $values): string
    {
        try {
            return json_encode($values, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('The finding list value could not be encoded.', 0, $e);
        }
    }

    private function requireAudit(): AuditLogger
    {
        if ($this->audit === null) {
            // Fail closed: SFR-AUD-001 requires finding, severity and
            // assignment changes to be audited, and a change nobody can
            // evidence is not one this class will make.
            throw new RuntimeException(
                'An AuditLogger must be injected before a finding decision can be recorded '
                . '(SFR-AUD-001).'
            );
        }

        return $this->audit;
    }

    /**
     * The default clock, in UTC. Callers that need determinism inject the
     * moment instead.
     */
    private function clock(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
