<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use DateTimeImmutable;
use InvalidArgumentException;

/**
 * The six dispositions SFR-REPORT-001 requires a report to tell apart, and the
 * single place that decides which one an item carries.
 *
 * THE REQUIREMENT THIS EXISTS TO SATISFY, VERBATIM
 * -------------------------------------------------
 * SFR-REPORT-001 [Must]: "Reports shall clearly distinguish confirmed,
 * suspected, informational, accepted, remediated, and not-retested items."
 *
 * Six words, six constants, and no seventh. A report that renders five of them
 * and quietly folds the sixth into a neighbour has not distinguished them.
 *
 * WHY THIS IS A CLASS AND NOT AN `if` INSIDE THE BUILDER
 * ------------------------------------------------------
 * Every one of the six reports answers the same question — "what is the state
 * of this item?" — and if each report answered it separately they would
 * eventually disagree. The executive summary counting a fix as remediated
 * while the retest register shows nobody verified it is not a cosmetic
 * inconsistency: it is the exact misreport this requirement exists to prevent.
 * One classifier, one answer, six renderings of it.
 *
 * WHY `not_retested` OUTRANKS `remediated` (THE LOAD-BEARING RULE)
 * -----------------------------------------------------------------
 * A fix nobody verified must NOT read as remediated. The owner of a
 * remediation is the party with an interest in it being finished, so
 * "fix_applied" is a claim, not a fact — the same reasoning that makes
 * RemediationTracker read closure off retest evidence rather than off the
 * caller's say-so (FRD section 7). This class therefore asks the tracker
 * whether closure is evidenced and reports NOT_RETESTED whenever it is not,
 * even though the remediation's own status column says a fix was applied.
 *
 * Only a remediation the repository actually marked `verified` — which
 * RemediationRepository::verify() will not write without a passing,
 * evidence-bearing retest — earns REMEDIATED.
 *
 * WHY PRECEDENCE IS DECLARED AND ORDERED
 * ---------------------------------------
 * An item can qualify for several dispositions at once: a confirmed finding
 * with a live waiver and a half-finished fix is all three of confirmed,
 * accepted and not-retested. Reports must not render whichever branch the
 * author wrote first, so the order below is explicit, justified and pinned by
 * a test. Reading down the list is reading the policy.
 *
 * NOTHING HERE IS RE-DERIVED
 * ---------------------------
 * Every input is read from an existing sanctioned accessor —
 * Finding::status()/isConfirmed(), Remediation::isVerified()/isOpen(),
 * RiskAcceptance::isActiveAt(), RemediationTracker::closureBlocker(). This
 * class adds an ordering, not a second opinion. A rule re-implemented here
 * would be a rule that can drift from the one the repository enforces.
 *
 * PURE, LIKE EVERY OTHER DECIDER IN THIS MODULE. No PDO, no clock of its own,
 * no socket: the moment is always a parameter, so a report of "as at last
 * quarter end" classifies exactly as the quarter-end report did.
 *
 * © AI WebScapes 2026
 */
final class ReportDisposition
{
    /**
     * A human validated it (Finding::STATUS_CONFIRMED). BRD section 5:
     * "automated severity is advisory until validated according to the service
     * plan" — confirmation is the validation, and it is a person's act.
     */
    public const CONFIRMED = 'confirmed';

    /**
     * Reported by a tool, not yet validated by a person. The honest label for
     * an open finding: the machine believes it, nobody has checked.
     */
    public const SUSPECTED = 'suspected';

    /** Carries no risk rating to act on (Finding::SEVERITY_INFORMATIONAL). */
    public const INFORMATIONAL = 'informational';

    /** A live, unexpired, unrevoked risk acceptance covers it (SBR-5.3). */
    public const ACCEPTED = 'accepted';

    /** Fixed AND verified by a passing, evidence-bearing retest. */
    public const REMEDIATED = 'remediated';

    /**
     * A fix was claimed but no passing evidenced retest closes it. The
     * disposition that exists precisely so an unverified fix cannot be read as
     * a finished one.
     */
    public const NOT_RETESTED = 'not_retested';

    /**
     * The six of SFR-REPORT-001, in the sentence's own order.
     *
     * @var list<string>
     */
    public const DISPOSITIONS = [
        self::CONFIRMED,
        self::SUSPECTED,
        self::INFORMATIONAL,
        self::ACCEPTED,
        self::REMEDIATED,
        self::NOT_RETESTED,
    ];

    /**
     * Human-facing labels. Explicit rather than derived from the constant so
     * "not_retested" never reaches a client report as the string
     * "Not retested" by accident of formatting — and so the wording that says
     * "nobody verified this" is reviewable in one place.
     *
     * @var array<string, string>
     */
    public const LABELS = [
        self::CONFIRMED => 'Confirmed',
        self::SUSPECTED => 'Suspected (not yet validated)',
        self::INFORMATIONAL => 'Informational',
        self::ACCEPTED => 'Risk accepted',
        self::REMEDIATED => 'Remediated (retest passed)',
        self::NOT_RETESTED => 'Fix applied, NOT retested',
    ];

    private RemediationTracker $tracker;

    public function __construct(?RemediationTracker $tracker = null)
    {
        $this->tracker = $tracker ?? new RemediationTracker();
    }

    /**
     * The disposition of one finding at one moment.
     *
     * THE PRECEDENCE, IN ORDER, WITH THE REASON FOR EACH RUNG:
     *
     *  1. REMEDIATED    — a verified fix. Highest because it is the only rung
     *                     that required evidence to reach; it is a fact about
     *                     the world, not a state of play. Reached only when
     *                     the remediation is `verified` AND the retest history
     *                     independently supports closure, so a status column
     *                     edited without evidence still cannot produce it.
     *  2. NOT_RETESTED  — a fix was claimed but is unverified. ABOVE accepted
     *                     and confirmed because it is the warning the report
     *                     exists to carry: this looks done and is not. Letting
     *                     "confirmed" outrank it would hide the very item
     *                     SFR-REPORT-001 names.
     *  3. ACCEPTED      — a live waiver. Below not-retested because a waiver
     *                     is a decision to tolerate a KNOWN state, and an
     *                     unverified fix means the state is not known.
     *  4. INFORMATIONAL — no risk rating to act on. Below acceptance so an
     *                     informational item under an explicit waiver still
     *                     shows as accepted (somebody decided about it).
     *  5. CONFIRMED     — validated by a person, still outstanding.
     *  6. SUSPECTED     — the floor. Anything not otherwise described is a
     *                     machine's unvalidated opinion, which is the most
     *                     conservative thing a report can say about an item.
     *
     * @param list<Retest>         $retests     Every retest against the
     *                                          remediation, in any order.
     * @param list<RiskAcceptance> $acceptances Every acceptance on the
     *                                          finding, in any order.
     */
    public function forFinding(
        Finding $finding,
        ?Remediation $remediation,
        array $retests,
        array $acceptances,
        DateTimeImmutable $now
    ): string {
        // 1. Verified AND evidenced. Both halves are required: the status
        //    column alone is a claim, and RemediationTracker is the authority
        //    on whether the evidence backs it (FRD section 7).
        if ($remediation !== null && $remediation->isVerified()) {
            if ($this->tracker->closureBlocker($retests) === null) {
                return self::REMEDIATED;
            }

            // Verified in the column but not evidenced in the history. Fail
            // closed to the warning, never up to REMEDIATED.
            return self::NOT_RETESTED;
        }

        // 2. A fix was claimed but nothing passing and evidenced closes it.
        //    This is the rung that stops an unverified fix reading as done.
        if ($remediation !== null && $this->claimsAFix($remediation)) {
            return self::NOT_RETESTED;
        }

        // 3. A live waiver, read off the clock rather than a stored flag, so a
        //    lapsed acceptance stops suppressing the moment it expires.
        if ($this->tracker->isRiskAccepted($acceptances, $now)) {
            return self::ACCEPTED;
        }

        // 4. Nothing to act on.
        if ($finding->severity() === Finding::SEVERITY_INFORMATIONAL) {
            return self::INFORMATIONAL;
        }

        // 5. A person validated it and it is still outstanding.
        if ($finding->isConfirmed()) {
            return self::CONFIRMED;
        }

        // 6. The conservative floor.
        return self::SUSPECTED;
    }

    /**
     * Whether the remediation asserts a fix that a retest has not closed.
     *
     * `fix_applied` is the explicit claim. A remediation the FINDING already
     * calls remediated counts too: the finding's status was moved by a human
     * (Finding::HUMAN_ONLY_STATUSES) and that act does not itself produce
     * retest evidence.
     */
    private function claimsAFix(Remediation $remediation): bool
    {
        return $remediation->status() === Remediation::STATUS_FIX_APPLIED;
    }

    /**
     * The disposition counts for a set of already-classified items, in the
     * canonical order, INCLUDING the zeroes.
     *
     * The zeroes are the point. A summary that omits empty dispositions lets
     * "not-retested: 0" and "we did not compute not-retested" look identical
     * on the page, which is how an absent control comes to read as a passing
     * one.
     *
     * @param list<string> $dispositions
     *
     * @return array<string, int>
     */
    public function tally(array $dispositions): array
    {
        $counts = [];
        foreach (self::DISPOSITIONS as $disposition) {
            $counts[$disposition] = 0;
        }

        foreach ($dispositions as $disposition) {
            self::assertKnown($disposition);
            $counts[$disposition]++;
        }

        return $counts;
    }

    /**
     * The human-facing label for a disposition.
     *
     * @throws InvalidArgumentException When the disposition is not one of the
     *         six (AC-002: an unknown value is refused, never passed through).
     */
    public static function label(string $disposition): string
    {
        self::assertKnown($disposition);

        return self::LABELS[$disposition];
    }

    /**
     * @throws InvalidArgumentException When the value is not one of the six.
     */
    public static function assertKnown(string $disposition): void
    {
        if (!in_array($disposition, self::DISPOSITIONS, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown report disposition "%s". SFR-REPORT-001 names exactly six: %s '
                . '(allowlist, AC-002).',
                $disposition,
                implode(', ', self::DISPOSITIONS)
            ));
        }
    }
}
