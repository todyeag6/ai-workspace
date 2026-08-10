<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use DateInterval;
use DateTimeImmutable;
use InvalidArgumentException;
use RuntimeException;

/**
 * The Remediation Tracker's decision half: "Status, owner, comments,
 * exceptions, due dates, retest" (FRD section 2), implementing the rules of
 * SFR-RETEST-001, SBR-5.3 and the FRD section 7 closure acceptance test.
 *
 * WHY THIS COMPONENT DECIDES AND NEVER PERSISTS
 * ----------------------------------------------
 * Same decide-not-act split as FindingEngine, ScopeManager, SafetyMonitor and
 * EvidenceProcessor: RemediationRepository moves rows, this class judges. It
 * holds no PDO handle, opens no socket and reads no clock — every moment is a
 * parameter. That is what makes the closure rule, the expiry arithmetic and
 * the status machine provable without a database, a tenant or a scanner.
 *
 * THE ONE THING THIS CLASS EXISTS TO GUARANTEE
 * ---------------------------------------------
 * FRD section 7: "Closure requires passing evidence linked to remediation."
 * assertMayClose() is the single place that sentence is enforced, and it reads
 * all three of its clauses off real retest records rather than trusting the
 * caller's claim:
 *   - a retest linked to this remediation must EXIST      (REASON_NO_RETEST)
 *   - its latest result must be a PASS                    (REASON_NOT_PASSING)
 *   - that pass must carry EVIDENCE                       (REASON_NO_EVIDENCE)
 * The party asking to close a finding is precisely the party with an interest
 * in closing it, so its say-so is not the input — the evidence is.
 *
 * WHY THE LATEST RETEST DECIDES, NOT THE BEST ONE
 * ------------------------------------------------
 * canCloseOn() sorts by performedAt/id and reads the LAST result. If a fix
 * passed in March, regressed, and failed in June, the finding is not closable
 * — even though a passing retest exists in the history. Searching the history
 * for any pass would let a stale success outrank current evidence of failure,
 * which is the same "flattering reading of history" failure mode SFR-FIND-002
 * guards against on the finding side.
 *
 * WHY THE SLA IS INHERITED FROM THE FINDING
 * ------------------------------------------
 * dueDateFor() returns the finding's OWN sla_due_at (SBR-5.1, computed by
 * FindingEngine from the ratified config/security/FINDING_SLA.php). A
 * remediation does not get to invent a looser deadline than the finding it
 * fixes: two dates for one obligation makes "mean time to remediate" (BRD
 * section 7) unmeasurable, and the flattering number always wins.
 *
 * WHY THE ACCEPTANCE WINDOW IS INJECTED
 * --------------------------------------
 * SBR-5.3 requires an expiry and a review date but names no durations, and the
 * approved baseline specifies no numbers. They therefore come from
 * config/security/REMEDIATION_POLICY.php — a ratifiable file with a cited
 * source — never from a constant here, exactly as FindingEngine takes its SLA
 * hours from config.
 *
 * © AI WebScapes 2026
 */
final class RemediationTracker
{
    /**
     * The status transitions a remediation may make (AC-002: an allowlist, so
     * an unlisted transition is refused rather than permitted by omission).
     *
     * Note what is NOT here: nothing leads out of `verified`. A verified fix
     * that regresses is a NEW observation of the issue, which the Finding
     * Engine records as a new occurrence on the finding (SFR-FIND-002) — it
     * does not rewrite the history of the fix that did work at the time.
     *
     * @var array<string, list<string>>
     */
    private const ALLOWED_TRANSITIONS = [
        Remediation::STATUS_PLANNED => [
            Remediation::STATUS_IN_PROGRESS,
            Remediation::STATUS_BLOCKED,
            Remediation::STATUS_CANCELLED,
        ],
        Remediation::STATUS_IN_PROGRESS => [
            Remediation::STATUS_FIX_APPLIED,
            Remediation::STATUS_BLOCKED,
            Remediation::STATUS_CANCELLED,
        ],
        // A claimed fix can go straight to verified (with evidence), or back
        // to in_progress when a retest fails.
        Remediation::STATUS_FIX_APPLIED => [
            Remediation::STATUS_VERIFIED,
            Remediation::STATUS_IN_PROGRESS,
            Remediation::STATUS_BLOCKED,
            Remediation::STATUS_CANCELLED,
        ],
        Remediation::STATUS_BLOCKED => [
            Remediation::STATUS_IN_PROGRESS,
            Remediation::STATUS_CANCELLED,
        ],
        // Terminal. See the class comment.
        Remediation::STATUS_VERIFIED => [],
        Remediation::STATUS_CANCELLED => [],
    ];

    private int $maxAcceptanceDays;

    private int $defaultAcceptanceDays;

    private int $reviewLeadDays;

    /**
     * @param array<string, int>|null $policy Remediation policy values.
     *        Defaults to the ratifiable config/security/REMEDIATION_POLICY.php
     *        (SBR-5.3), so production honours the file without the caller
     *        having to know it exists.
     */
    public function __construct(?array $policy = null)
    {
        $loaded = $policy ?? self::defaultPolicy();

        $this->maxAcceptanceDays = self::positiveInt($loaded, 'max_acceptance_days');
        $this->defaultAcceptanceDays = self::positiveInt($loaded, 'default_acceptance_days');
        $this->reviewLeadDays = self::positiveInt($loaded, 'review_lead_days');

        if ($this->defaultAcceptanceDays > $this->maxAcceptanceDays) {
            // Fail closed on an incoherent policy rather than silently
            // granting longer waivers than the ceiling allows.
            throw new InvalidArgumentException(
                'The default risk-acceptance period cannot exceed the maximum (SBR-5.3); '
                . 'check config/security/REMEDIATION_POLICY.php.'
            );
        }
    }

    /**
     * THE CLOSURE RULE (FRD section 7): may this finding be closed?
     *
     * Returns the reason it may NOT be closed, or null when it may. Expressed
     * as a nullable reason rather than a bare bool so the caller can tell an
     * operator WHICH condition failed — three different next actions.
     *
     * @param list<Retest> $retests Every retest recorded against the
     *                              remediation, in any order.
     */
    public function closureBlocker(array $retests): ?string
    {
        $latest = $this->latestRetest($retests);

        if ($latest === null) {
            return ClosureEvidenceRequired::REASON_NO_RETEST;
        }

        if ($latest->result() !== Retest::RESULT_PASS) {
            // Covers both `fail` and `inconclusive`. A run that determined
            // nothing (SFR-SCAN-003) closes nothing.
            return ClosureEvidenceRequired::REASON_NOT_PASSING;
        }

        if (!$latest->hasEvidence()) {
            return ClosureEvidenceRequired::REASON_NO_EVIDENCE;
        }

        return null;
    }

    /**
     * Whether the retest history permits closure.
     *
     * @param list<Retest> $retests
     */
    public function canClose(array $retests): bool
    {
        return $this->closureBlocker($retests) === null;
    }

    /**
     * The fail-closed form of the closure rule: throws unless the evidence is
     * there (FRD section 7).
     *
     * RemediationRepository calls this BEFORE writing a verified status, so
     * there is no code path that records a verified fix without the evidence
     * to back it.
     *
     * @param list<Retest> $retests
     *
     * @throws ClosureEvidenceRequired When closure is not evidenced.
     */
    public function assertMayClose(int $findingId, array $retests): void
    {
        $blocker = $this->closureBlocker($retests);

        if ($blocker === null) {
            return;
        }

        throw new ClosureEvidenceRequired(
            $blocker,
            $findingId,
            match ($blocker) {
                ClosureEvidenceRequired::REASON_NO_RETEST => sprintf(
                    'Finding %d cannot be closed: no retest has been recorded against its '
                    . 'remediation. Closure requires passing evidence linked to remediation '
                    . '(FRD section 7, SFR-RETEST-001).',
                    $findingId
                ),
                ClosureEvidenceRequired::REASON_NOT_PASSING => sprintf(
                    'Finding %d cannot be closed: its most recent retest did not pass. A failed '
                    . 'or inconclusive retest is not closure evidence (FRD section 7, '
                    . 'SFR-SCAN-003).',
                    $findingId
                ),
                default => sprintf(
                    'Finding %d cannot be closed: its passing retest carries no evidence. '
                    . 'Closure requires passing EVIDENCE linked to remediation, not an assertion '
                    . 'of success (FRD section 7, SFR-EVID-001).',
                    $findingId
                ),
            }
        );
    }

    /**
     * The most recent retest, or null when there are none.
     *
     * Ordered by when the retest was PERFORMED, with the row id as the
     * tie-break for two retests recorded at the same second.
     *
     * @param list<Retest> $retests
     */
    public function latestRetest(array $retests): ?Retest
    {
        $sorted = $retests;

        usort($sorted, static function (Retest $a, Retest $b): int {
            $byTime = $a->performedAt() <=> $b->performedAt();

            return $byTime !== 0 ? $byTime : $a->id() <=> $b->id();
        });

        return $sorted === [] ? null : $sorted[count($sorted) - 1];
    }

    /**
     * Whether a status transition is permitted (AC-002 allowlist).
     */
    public function mayTransition(string $from, string $to): bool
    {
        if (!in_array($from, Remediation::STATUSES, true)) {
            return false;
        }

        if (!in_array($to, Remediation::STATUSES, true)) {
            return false;
        }

        return in_array($to, self::ALLOWED_TRANSITIONS[$from], true);
    }

    /**
     * The fail-closed form of the transition rule.
     *
     * @throws RuntimeException When the transition is not in the allowlist.
     */
    public function assertMayTransition(string $from, string $to): void
    {
        if ($this->mayTransition($from, $to)) {
            return;
        }

        $permitted = self::ALLOWED_TRANSITIONS[$from] ?? [];

        throw new RuntimeException(sprintf(
            'A remediation cannot move from "%s" to "%s". Permitted from "%s": %s (allowlist, '
            . 'AC-002).',
            $from,
            $to,
            $from,
            $permitted === [] ? 'nothing - it is terminal' : implode(', ', $permitted)
        ));
    }

    /**
     * The remediation deadline for a finding: the finding's OWN SLA (SBR-5.1).
     *
     * Deliberately not a fresh calculation. See the class comment — the
     * remediation inherits the finding's deadline rather than inventing a
     * second, looser one.
     */
    public function dueDateFor(Finding $finding): ?DateTimeImmutable
    {
        return $finding->slaDueAt();
    }

    /**
     * The expiry and review dates for a new risk acceptance (SBR-5.3).
     *
     * $requestedExpiry is honoured when it is inside the ratified ceiling;
     * absent, the default period applies. A request BEYOND the ceiling is
     * refused rather than silently clamped: a caller asking for a three-year
     * waiver and receiving a one-year one without being told would believe the
     * risk was accepted for three years.
     *
     * @return array{review_at: DateTimeImmutable, expires_at: DateTimeImmutable}
     *
     * @throws InvalidArgumentException When the requested expiry is in the past
     *         or beyond the ratified maximum.
     */
    public function acceptanceWindow(
        DateTimeImmutable $grantedAt,
        ?DateTimeImmutable $requestedExpiry = null
    ): array {
        $ceiling = $grantedAt->add(new DateInterval('P' . $this->maxAcceptanceDays . 'D'));

        if ($requestedExpiry === null) {
            $expires = $grantedAt->add(new DateInterval('P' . $this->defaultAcceptanceDays . 'D'));
        } else {
            if ($requestedExpiry <= $grantedAt) {
                throw new InvalidArgumentException(
                    'A risk acceptance must expire after it is granted (SBR-5.3).'
                );
            }

            if ($requestedExpiry > $ceiling) {
                throw new InvalidArgumentException(sprintf(
                    'A risk acceptance may not run longer than %d days (SBR-5.3, '
                    . 'config/security/REMEDIATION_POLICY.php). Requested expiry %s exceeds the '
                    . 'ceiling of %s. Grant a shorter acceptance and renew it, or raise the '
                    . 'policy in a reviewed change.',
                    $this->maxAcceptanceDays,
                    $requestedExpiry->format('Y-m-d'),
                    $ceiling->format('Y-m-d')
                ));
            }

            $expires = $requestedExpiry;
        }

        $review = $expires->sub(new DateInterval('P' . $this->reviewLeadDays . 'D'));

        // A short acceptance can have its review date fall before it was even
        // granted. Clamp to the grant moment: the review is then immediate,
        // which is the correct reading for a waiver shorter than the lead time.
        if ($review < $grantedAt) {
            $review = $grantedAt;
        }

        return ['review_at' => $review, 'expires_at' => $expires];
    }

    /**
     * Whether a finding is currently suppressed by a live risk acceptance
     * (SBR-5.3).
     *
     * Reads BOTH the revocation status and the clock — see
     * RiskAcceptance::isActiveAt() for why a stored "expired" flag would be
     * unsafe.
     *
     * @param list<RiskAcceptance> $acceptances
     */
    public function isRiskAccepted(array $acceptances, DateTimeImmutable $now): bool
    {
        foreach ($acceptances as $acceptance) {
            if ($acceptance->isActiveAt($now)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The acceptances that need a human's attention at this moment: due for
     * review, or already lapsed while still marked active (SBR-5.3).
     *
     * The tracker DECIDES that a review is owed; chasing it is somebody else's
     * job — this class opens no socket.
     *
     * @param list<RiskAcceptance> $acceptances
     *
     * @return list<RiskAcceptance>
     */
    public function acceptancesNeedingReview(array $acceptances, DateTimeImmutable $now): array
    {
        $due = [];

        foreach ($acceptances as $acceptance) {
            if ($acceptance->status() !== RiskAcceptance::STATUS_ACTIVE) {
                continue;
            }

            if ($acceptance->isDueForReviewAt($now) || $acceptance->hasExpiredAt($now)) {
                $due[] = $acceptance;
            }
        }

        usort(
            $due,
            static fn (RiskAcceptance $a, RiskAcceptance $b): int => $a->expiresAt() <=> $b->expiresAt()
        );

        return $due;
    }

    /**
     * Remediations past their deadline at this moment (SBR-5.1, BRD section 7
     * "mean time to remediate").
     *
     * @param list<Remediation> $remediations
     *
     * @return list<Remediation>
     */
    public function overdue(array $remediations, DateTimeImmutable $now): array
    {
        $late = [];

        foreach ($remediations as $remediation) {
            if ($remediation->isOverdue($now)) {
                $late[] = $remediation;
            }
        }

        usort($late, static function (Remediation $a, Remediation $b): int {
            $aDue = $a->dueAt();
            $bDue = $b->dueAt();

            if ($aDue === null || $bDue === null) {
                return $a->id() <=> $b->id();
            }

            return $aDue <=> $bDue;
        });

        return $late;
    }

    public function maxAcceptanceDays(): int
    {
        return $this->maxAcceptanceDays;
    }

    public function defaultAcceptanceDays(): int
    {
        return $this->defaultAcceptanceDays;
    }

    public function reviewLeadDays(): int
    {
        return $this->reviewLeadDays;
    }

    /**
     * The ratifiable policy from config/security/REMEDIATION_POLICY.php.
     *
     * @return array<string, int>
     */
    private static function defaultPolicy(): array
    {
        $path = dirname(__DIR__, 2) . '/config/security/REMEDIATION_POLICY.php';

        if (!is_file($path)) {
            throw new RuntimeException(sprintf(
                'The remediation policy file is missing at "%s"; acceptance periods are '
                . 'configured, not hardcoded (SBR-5.3).',
                $path
            ));
        }

        /** @var mixed $loaded */
        $loaded = require $path;

        if (!is_array($loaded)) {
            throw new RuntimeException('The remediation policy file must return an array.');
        }

        $policy = [];
        foreach ($loaded as $key => $value) {
            if (is_string($key) && is_int($value)) {
                $policy[$key] = $value;
            }
        }

        return $policy;
    }

    /**
     * @param array<string, int> $policy
     */
    private static function positiveInt(array $policy, string $key): int
    {
        if (!array_key_exists($key, $policy)) {
            // Fail closed: a missing period would otherwise become an
            // unbounded or zero-length waiver depending on the reader.
            throw new InvalidArgumentException(sprintf(
                'The remediation policy does not define "%s" (SBR-5.3).',
                $key
            ));
        }

        $value = $policy[$key];
        if ($value <= 0) {
            throw new InvalidArgumentException(sprintf(
                'The remediation policy value "%s" must be a positive number of days.',
                $key
            ));
        }

        return $value;
    }
}
