<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Audit\AuditLogger;
use App\Data\TenantRepository;
use DateTimeImmutable;
use DateTimeZone;
use PDO;
use RuntimeException;

/**
 * The Remediation Tracker's persistence half: remediation plans, and the
 * composed registers for retests, risk acceptances and comments (FRD section 2
 * "Status, owner, comments, exceptions, due dates, retest").
 *
 * WHAT THIS CLASS IS FOR, AND WHAT IT REFUSES TO DO
 * -------------------------------------------------
 * It moves rows. RemediationTracker decides. The one thing this class adds on
 * top of storage is that it will not write a decision the tracker has not
 * sanctioned — specifically:
 *
 *   verify() calls RemediationTracker::assertMayClose() BEFORE the UPDATE, so
 *   there is no code path in this application that marks a remediation
 *   verified without a passing, evidence-bearing retest linked to it
 *   (FRD section 7). The check is not advisory and the caller cannot skip it,
 *   because the caller never gets to write the status column directly.
 *
 * WHY THE CHILD REPOSITORIES ARE BUILT, NOT INJECTED
 * ---------------------------------------------------
 * Each of retests, risk_acceptances and remediation_comments is its own table
 * and therefore its own TenantRepository subclass (AC-001). They are
 * constructed here from this repository's own $pdo and $tenantId, exactly as
 * FindingRepository builds FindingOccurrenceRepository, so a caller cannot
 * hand in a child scoped to a DIFFERENT tenant and write across the boundary.
 *
 * WHY THE HUMAN IS REQUIRED AT THIS LAYER TOO
 * --------------------------------------------
 * SFR-AI-001 reserves confirming, closing and accepting risk for people. Every
 * method here that asserts something about the world — fix applied, verified,
 * risk accepted, acceptance revoked — refuses an empty decider with
 * HumanDecisionRequired, the same fail-closed shape FindingRepository uses.
 *
 * © AI WebScapes 2026
 */
final class RemediationRepository extends TenantRepository
{
    public const AUDIT_OPEN = 'remediation.open';
    public const AUDIT_STATUS = 'remediation.status.change';
    public const AUDIT_VERIFY = 'remediation.verify';
    public const AUDIT_RETEST = 'remediation.retest.record';
    public const AUDIT_ACCEPT = 'remediation.risk.accept';
    public const AUDIT_REVOKE = 'remediation.risk.revoke';
    public const AUDIT_COMMENT = 'remediation.comment.add';

    private const AUDIT_SOURCE = 'remediation_repository';

    private const AUDIT_OBJECT_TYPE = 'remediation';

    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    private RetestRepository $retests;

    private RiskAcceptanceRepository $acceptances;

    private RemediationCommentRepository $comments;

    private RemediationTracker $tracker;

    private ?AuditLogger $audit;

    /** @var array<string, int> */
    private array $policy;

    /**
     * @param AuditLogger|null     $audit  Required by every human-decision
     *                                     path, which refuses to run
     *                                     unevidenced (SFR-AUD-001).
     * @param array<string, int>|null $policy Overrides
     *                                     config/security/REMEDIATION_POLICY.php,
     *                                     for tests.
     */
    public function __construct(
        PDO $pdo,
        ?int $tenantId,
        ?AuditLogger $audit = null,
        ?RemediationTracker $tracker = null,
        ?array $policy = null
    ) {
        parent::__construct($pdo, $tenantId);

        // Built here rather than injected: see the class comment.
        $this->retests = new RetestRepository($pdo, $tenantId);
        $this->acceptances = new RiskAcceptanceRepository($pdo, $tenantId);
        $this->comments = new RemediationCommentRepository($pdo, $tenantId);

        $this->tracker = $tracker ?? new RemediationTracker($policy);
        $this->audit = $audit;
        $this->policy = $policy ?? self::loadPolicy();
    }

    protected function table(): string
    {
        return 'remediations';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'finding_id',
            'owner',
            'plan',
            'due_at',
            'change_reference',
            'status',
            'created_by',
            'verified_by',
            'verified_at',
            'created_at',
            'updated_at',
        ];
    }

    /**
     * Opens the remediation plan for a finding, or returns the existing one.
     *
     * The due date is INHERITED from the finding's own SLA (SBR-5.1) rather
     * than invented here — see RemediationTracker::dueDateFor().
     *
     * Idempotent by design: the schema allows one plan per finding, so a
     * second call returns the first plan's id instead of failing. Re-observing
     * an issue must not be able to error just because somebody already started
     * fixing it.
     */
    public function open(
        Finding $finding,
        string $owner,
        string $createdBy,
        ?string $plan = null,
        ?string $changeReference = null,
        ?DateTimeImmutable $openedAt = null,
        ?int $actorUserId = null
    ): int {
        $existing = $this->findByFinding($finding->id());
        if ($existing !== null) {
            return $existing->id();
        }

        $human = trim($createdBy);
        if ($human === '') {
            throw new HumanDecisionRequired(
                Remediation::STATUS_PLANNED,
                'Opening a remediation plan requires a named human (SFR-AUD-001).'
            );
        }

        $moment = $openedAt ?? $this->clock();
        $due = $this->tracker->dueDateFor($finding);

        $id = (int) $this->insertScoped([
            'finding_id' => $finding->id(),
            'owner' => trim($owner),
            'plan' => $plan === null ? null : mb_substr(trim($plan), 0, $this->limit('max_plan_chars')),
            'due_at' => $due?->format(self::TIMESTAMP_FORMAT),
            'change_reference' => $changeReference === null ? null : trim($changeReference),
            'status' => Remediation::STATUS_PLANNED,
            'created_by' => $human,
            'created_at' => $moment->format(self::TIMESTAMP_FORMAT),
            'updated_at' => $moment->format(self::TIMESTAMP_FORMAT),
        ]);

        $this->requireAudit()->record(
            $this->tenantId(),
            $actorUserId,
            self::AUDIT_OPEN,
            self::AUDIT_OBJECT_TYPE,
            (string) $id,
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf(
                'remediation %d opened for finding %d by %s, owner %s, due %s',
                $id,
                $finding->id(),
                $human,
                trim($owner) === '' ? '(unassigned)' : trim($owner),
                $due?->format(self::TIMESTAMP_FORMAT) ?? 'none'
            )
        );

        return $id;
    }

    /**
     * Moves a remediation through its status machine (FRD section 4 "status").
     *
     * Two gates, both fail-closed:
     *   1. the transition must be in the tracker's allowlist (AC-002), and
     *   2. a status that asserts something about the world needs a named human
     *      (SFR-AI-001).
     *
     * `verified` is deliberately NOT reachable here — it has its own method,
     * because it needs evidence, not just a decider.
     *
     * @throws HumanDecisionRequired When a human-only status has no human.
     * @throws RuntimeException      When the transition is not permitted.
     */
    public function transitionStatus(
        int $id,
        string $status,
        string $decidedBy,
        ?int $actorUserId = null,
        ?DateTimeImmutable $decidedAt = null,
        string $reason = ''
    ): void {
        if ($status === Remediation::STATUS_VERIFIED) {
            // Routing a caller who tries the back door to the front one.
            throw new ClosureEvidenceRequired(
                ClosureEvidenceRequired::REASON_NO_RETEST,
                $this->requireById($id)->findingId(),
                'A remediation cannot be set to "verified" directly. Closure requires passing '
                . 'evidence linked to remediation, so verification goes through verify(), which '
                . 'checks the retest record (FRD section 7).'
            );
        }

        $remediation = $this->requireById($id);
        $human = trim($decidedBy);

        if (in_array($status, Remediation::HUMAN_ONLY_STATUSES, true) && $human === '') {
            throw new HumanDecisionRequired(
                $status,
                sprintf(
                    'Moving a remediation to "%s" asserts something about the world and requires '
                    . 'a named human (SFR-AI-001).',
                    $status
                )
            );
        }

        // Throws when the move is not in the allowlist.
        $this->tracker->assertMayTransition($remediation->status(), $status);

        $moment = $decidedAt ?? $this->clock();

        $this->updateScoped(
            [
                'status' => $status,
                'updated_at' => $moment->format(self::TIMESTAMP_FORMAT),
            ],
            'id = :id',
            ['id' => $id]
        );

        $this->requireAudit()->record(
            $this->tenantId(),
            $actorUserId,
            self::AUDIT_STATUS,
            self::AUDIT_OBJECT_TYPE,
            (string) $id,
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf(
                'remediation %d %s -> %s by %s%s',
                $id,
                $remediation->status(),
                $status,
                $human === '' ? '(system)' : $human,
                $reason === '' ? '' : ': ' . $reason
            )
        );
    }

    /**
     * Records one retest result against a remediation (SFR-RETEST-001).
     *
     * A failing retest also walks the plan back to in_progress: the fix was
     * claimed and did not hold, so leaving it at fix_applied would misstate
     * the position. The failed retest itself is never removed.
     */
    public function recordRetest(
        int $remediationId,
        int $scanProfileId,
        int $profileVersion,
        string $result,
        string $performedBy,
        ?int $scanId = null,
        ?int $evidenceId = null,
        ?string $evidenceHash = null,
        ?string $note = null,
        ?DateTimeImmutable $performedAt = null,
        ?int $actorUserId = null
    ): int {
        $remediation = $this->requireById($remediationId);
        $moment = $performedAt ?? $this->clock();

        // Throws for an unnamed tester, an unknown result, or — the load-bearing
        // one — a pass with no evidence (FRD section 7).
        $retestId = $this->retests->record(
            $remediation->findingId(),
            $remediationId,
            $scanProfileId,
            $profileVersion,
            $result,
            $performedBy,
            $moment,
            $scanId,
            $evidenceId,
            $evidenceHash,
            $note
        );

        if (
            $result === Retest::RESULT_FAIL
            && $remediation->status() === Remediation::STATUS_FIX_APPLIED
        ) {
            $this->updateScoped(
                [
                    'status' => Remediation::STATUS_IN_PROGRESS,
                    'updated_at' => $moment->format(self::TIMESTAMP_FORMAT),
                ],
                'id = :id',
                ['id' => $remediationId]
            );
        }

        $this->requireAudit()->record(
            $this->tenantId(),
            $actorUserId,
            self::AUDIT_RETEST,
            self::AUDIT_OBJECT_TYPE,
            (string) $remediationId,
            $result === Retest::RESULT_PASS ? 'success' : 'failure',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf(
                'retest %d on remediation %d: %s by %s (profile %d v%d)',
                $retestId,
                $remediationId,
                $result,
                trim($performedBy),
                $scanProfileId,
                $profileVersion
            )
        );

        return $retestId;
    }

    /**
     * THE CLOSURE PATH (FRD section 7): marks a remediation verified, but only
     * on the strength of a passing, evidence-bearing retest linked to it.
     *
     * The evidence is READ from the retest table, not accepted from the
     * caller. A caller who wants this to succeed must first have recorded a
     * real retest — which itself refuses to be a pass without evidence.
     *
     * @throws ClosureEvidenceRequired When the retest record does not support
     *         closure — the fail-closed path.
     * @throws HumanDecisionRequired   When no human is named.
     */
    public function verify(
        int $id,
        string $verifiedBy,
        ?int $actorUserId = null,
        ?DateTimeImmutable $verifiedAt = null
    ): void {
        $remediation = $this->requireById($id);

        $human = trim($verifiedBy);
        if ($human === '') {
            throw new HumanDecisionRequired(
                Remediation::STATUS_VERIFIED,
                'Verifying a remediation is a human decision (SFR-AI-001); no automated caller '
                . 'may close a finding.'
            );
        }

        // The gate. Throws unless a passing, evidence-bearing retest exists.
        $this->tracker->assertMayClose(
            $remediation->findingId(),
            $this->retests->forRemediation($id)
        );

        $this->tracker->assertMayTransition($remediation->status(), Remediation::STATUS_VERIFIED);

        $moment = $verifiedAt ?? $this->clock();

        $this->updateScoped(
            [
                'status' => Remediation::STATUS_VERIFIED,
                'verified_by' => $human,
                'verified_at' => $moment->format(self::TIMESTAMP_FORMAT),
                'updated_at' => $moment->format(self::TIMESTAMP_FORMAT),
            ],
            'id = :id',
            ['id' => $id]
        );

        $this->requireAudit()->record(
            $this->tenantId(),
            $actorUserId,
            self::AUDIT_VERIFY,
            self::AUDIT_OBJECT_TYPE,
            (string) $id,
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf(
                'remediation %d verified by %s on evidenced passing retest (finding %d)',
                $id,
                $human,
                $remediation->findingId()
            )
        );
    }

    /**
     * Grants a formal risk acceptance against a finding (SBR-5.3).
     *
     * The window comes from RemediationTracker, which reads the ratified
     * policy — a caller cannot grant a waiver longer than the ceiling, and one
     * that asks for a longer one is refused rather than silently clamped.
     */
    public function acceptRisk(
        int $findingId,
        string $approver,
        string $rationale,
        string $compensatingControl,
        ?DateTimeImmutable $requestedExpiry = null,
        ?DateTimeImmutable $grantedAt = null,
        ?int $actorUserId = null
    ): int {
        $human = trim($approver);
        if ($human === '') {
            throw new HumanDecisionRequired(
                'risk_accepted',
                'Accepting a risk is a human decision and the approver must be named '
                . '(SFR-AI-001, SBR-5.3).'
            );
        }

        $moment = $grantedAt ?? $this->clock();
        $window = $this->tracker->acceptanceWindow($moment, $requestedExpiry);

        $id = $this->acceptances->grant(
            $findingId,
            $human,
            $rationale,
            $compensatingControl,
            $window['review_at'],
            $window['expires_at'],
            $moment,
            $this->limit('max_rationale_chars'),
            $this->limit('max_control_chars')
        );

        $this->requireAudit()->record(
            $this->tenantId(),
            $actorUserId,
            self::AUDIT_ACCEPT,
            'risk_acceptance',
            (string) $id,
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf(
                'risk acceptance %d granted on finding %d by %s, review %s, expires %s',
                $id,
                $findingId,
                $human,
                $window['review_at']->format(self::TIMESTAMP_FORMAT),
                $window['expires_at']->format(self::TIMESTAMP_FORMAT)
            )
        );

        return $id;
    }

    /**
     * Withdraws a risk acceptance before its expiry (SBR-5.3).
     */
    public function revokeRisk(
        int $acceptanceId,
        string $revokedBy,
        string $reason,
        ?DateTimeImmutable $revokedAt = null,
        ?int $actorUserId = null
    ): bool {
        $human = trim($revokedBy);
        if ($human === '') {
            throw new HumanDecisionRequired(
                RiskAcceptance::STATUS_REVOKED,
                'Revoking a risk acceptance is a human decision (SFR-AUD-001).'
            );
        }

        $moment = $revokedAt ?? $this->clock();
        $revoked = $this->acceptances->revoke($acceptanceId, $human, $reason, $moment);

        if ($revoked) {
            $this->requireAudit()->record(
                $this->tenantId(),
                $actorUserId,
                self::AUDIT_REVOKE,
                'risk_acceptance',
                (string) $acceptanceId,
                'success',
                self::AUDIT_SOURCE,
                null,
                [],
                [],
                sprintf('risk acceptance %d revoked by %s: %s', $acceptanceId, $human, trim($reason))
            );
        }

        return $revoked;
    }

    /**
     * Appends a comment to a remediation thread (FRD section 2 "comments").
     */
    public function comment(
        int $remediationId,
        string $author,
        string $body,
        ?DateTimeImmutable $postedAt = null,
        ?int $actorUserId = null
    ): int {
        $remediation = $this->requireById($remediationId);
        $moment = $postedAt ?? $this->clock();

        $id = $this->comments->add(
            $remediationId,
            $remediation->findingId(),
            $author,
            $body,
            $moment,
            $this->limit('max_comment_chars')
        );

        $this->requireAudit()->record(
            $this->tenantId(),
            $actorUserId,
            self::AUDIT_COMMENT,
            self::AUDIT_OBJECT_TYPE,
            (string) $remediationId,
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf('comment %d added to remediation %d by %s', $id, $remediationId, trim($author))
        );

        return $id;
    }

    /**
     * Reassigns the fix (FRD section 4 "owner").
     */
    public function assignOwner(
        int $id,
        string $owner,
        string $assignedBy,
        ?DateTimeImmutable $assignedAt = null,
        ?int $actorUserId = null
    ): void {
        $this->requireById($id);

        $human = trim($assignedBy);
        if ($human === '') {
            throw new HumanDecisionRequired(
                'owner',
                'Assigning remediation ownership requires a named human (SFR-AUD-001).'
            );
        }

        $moment = $assignedAt ?? $this->clock();

        $this->updateScoped(
            [
                'owner' => trim($owner),
                'updated_at' => $moment->format(self::TIMESTAMP_FORMAT),
            ],
            'id = :id',
            ['id' => $id]
        );

        $this->requireAudit()->record(
            $this->tenantId(),
            $actorUserId,
            self::AUDIT_STATUS,
            self::AUDIT_OBJECT_TYPE,
            (string) $id,
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf('remediation %d owner -> %s by %s', $id, trim($owner), $human)
        );
    }

    /**
     * Extends or brings forward the deadline (FRD section 4 "due").
     *
     * A deliberate, audited act — see Remediation's class comment for why a
     * remediation does not simply carry its own looser date.
     */
    public function reschedule(
        int $id,
        ?DateTimeImmutable $dueAt,
        string $decidedBy,
        string $reason,
        ?DateTimeImmutable $decidedAt = null,
        ?int $actorUserId = null
    ): void {
        $remediation = $this->requireById($id);

        $human = trim($decidedBy);
        if ($human === '') {
            throw new HumanDecisionRequired(
                'due_at',
                'Changing a remediation deadline requires a named human (SBR-5.1, SFR-AUD-001).'
            );
        }

        if (trim($reason) === '') {
            // A moved security deadline with no stated why is the change that
            // hides slippage.
            throw new RuntimeException(
                'Changing a remediation deadline requires a stated reason (SBR-5.1).'
            );
        }

        $moment = $decidedAt ?? $this->clock();

        $this->updateScoped(
            [
                'due_at' => $dueAt?->format(self::TIMESTAMP_FORMAT),
                'updated_at' => $moment->format(self::TIMESTAMP_FORMAT),
            ],
            'id = :id',
            ['id' => $id]
        );

        $this->requireAudit()->record(
            $this->tenantId(),
            $actorUserId,
            self::AUDIT_STATUS,
            self::AUDIT_OBJECT_TYPE,
            (string) $id,
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            sprintf(
                'remediation %d due %s -> %s by %s: %s',
                $id,
                $remediation->dueAt()?->format(self::TIMESTAMP_FORMAT) ?? 'none',
                $dueAt?->format(self::TIMESTAMP_FORMAT) ?? 'none',
                $human,
                trim($reason)
            )
        );
    }

    /**
     * Null both when the remediation does not exist and when it belongs to
     * another tenant — deliberately indistinguishable (AC-001).
     */
    public function findById(int $id): ?Remediation
    {
        $rows = $this->selectScoped('id = :id', ['id' => $id]);

        return $rows === [] ? null : Remediation::fromRow($rows[0]);
    }

    /**
     * The plan for one finding, if one has been opened.
     */
    public function findByFinding(int $findingId): ?Remediation
    {
        $rows = $this->selectScoped('finding_id = :finding_id', ['finding_id' => $findingId]);

        return $rows === [] ? null : Remediation::fromRow($rows[0]);
    }

    /**
     * Every remediation in the tenant, oldest first.
     *
     * @return list<Remediation>
     */
    public function all(): array
    {
        $remediations = [];
        foreach ($this->selectScoped() as $row) {
            $remediations[] = Remediation::fromRow($row);
        }

        // Sorted in PHP: selectScoped() parenthesises the predicate, so an
        // ORDER BY inside it would be invalid SQL.
        usort($remediations, static fn (Remediation $a, Remediation $b): int => $a->id() <=> $b->id());

        return $remediations;
    }

    /**
     * Remediations past their deadline right now (SBR-5.1).
     *
     * @return list<Remediation>
     */
    public function overdue(?DateTimeImmutable $now = null): array
    {
        return $this->tracker->overdue($this->all(), $now ?? $this->clock());
    }

    /**
     * Whether a finding is currently suppressed by a live risk acceptance
     * (SBR-5.3).
     */
    public function isRiskAccepted(int $findingId, ?DateTimeImmutable $now = null): bool
    {
        return $this->tracker->isRiskAccepted(
            $this->acceptances->forFinding($findingId),
            $now ?? $this->clock()
        );
    }

    /**
     * Read access to the composed registers, for reporting.
     */
    public function retests(): RetestRepository
    {
        return $this->retests;
    }

    public function riskAcceptances(): RiskAcceptanceRepository
    {
        return $this->acceptances;
    }

    public function comments(): RemediationCommentRepository
    {
        return $this->comments;
    }

    /**
     * @throws RuntimeException When the remediation is not visible in this
     *         tenant.
     */
    private function requireById(int $id): Remediation
    {
        $remediation = $this->findById($id);

        if ($remediation === null) {
            // Same message whether it is absent or another tenant's: the
            // difference is not the caller's to learn (AC-001).
            throw new RuntimeException(sprintf('Remediation %d is not visible in this tenant.', $id));
        }

        return $remediation;
    }

    private function limit(string $key): int
    {
        $value = $this->policy[$key] ?? 0;

        return $value > 0 ? $value : 2000;
    }

    private function requireAudit(): AuditLogger
    {
        if ($this->audit === null) {
            // Fail closed: SFR-AUD-001 requires remediation decisions to be
            // audited, and a change nobody can evidence is not one this class
            // will make.
            throw new RuntimeException(
                'An AuditLogger must be injected before a remediation decision can be recorded '
                . '(SFR-AUD-001).'
            );
        }

        return $this->audit;
    }

    /**
     * @return array<string, int>
     */
    private static function loadPolicy(): array
    {
        $path = dirname(__DIR__, 2) . '/config/security/REMEDIATION_POLICY.php';

        if (!is_file($path)) {
            return [];
        }

        /** @var mixed $loaded */
        $loaded = require $path;

        if (!is_array($loaded)) {
            return [];
        }

        $policy = [];
        foreach ($loaded as $key => $value) {
            if (is_string($key) && is_int($value)) {
                $policy[$key] = $value;
            }
        }

        return $policy;
    }

    private function clock(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
