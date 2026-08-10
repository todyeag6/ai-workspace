<?php

/**
 * P3-T7 Remediation Tracker — remediation, retest and risk-acceptance policy.
 *
 * SOURCE OF THE REQUIREMENT: FRD section 2 gives the Remediation Tracker the
 * job "Status, owner, comments, exceptions, due dates, retest", and section 4
 * enumerates the fields of `remediations`, `risk_acceptances` and `retests`.
 * The BRD adds the governing rules:
 *
 *   SBR-003  [Must] Reduce time from finding to verified remediation.
 *   SBR-5.1  [Must] Critical and high findings shall generate configured
 *            alerts and remediation deadlines.
 *   SBR-5.3  [Must] Risk acceptance shall name approver, rationale,
 *            compensating control, review date, and expiry.
 *
 * And FRD section 7's acceptance test, which is the component's litmus:
 *
 *   Retest → "Closure requires passing evidence linked to remediation."
 *
 * IMPORTANT (do not "fix" by hardcoding these into the component): exactly as
 * with config/security/FINDING_SLA.php, the approved baseline specifies NO
 * numeric durations here. SBR-5.3 requires an expiry and a review date but
 * names no length; nothing in the baseline says how long a risk acceptance may
 * run. Those numbers are therefore a service-plan parameter, not a
 * requirement, and they live in this one auditable, change-controlled file
 * that a ratifier edits without touching RemediationTracker.
 *
 * STATUS: RATIFIED 2026-08-10 by the platform owner. The values below are now
 * approved policy, not proposed defaults. tests/SecurityAgent/
 * RemediationTrackerTest.php::test_shipped_remediation_policy_pins_its_contract_terms
 * REMAINS IN FORCE and pins every value below, so changing one without
 * updating the test — and therefore without a reviewer seeing it — fails CI.
 * Ratification raises the bar on an edit; it does not remove it.
 *
 * ---------------------------------------------------------------------------
 * WHY A RISK ACCEPTANCE MUST EXPIRE, AND WHY THE CEILING IS ONE YEAR
 * ---------------------------------------------------------------------------
 * An accepted risk with no end date is a permanent silent waiver: the finding
 * stops appearing in anyone's queue, and the decision is never revisited even
 * as the surrounding system changes. SBR-5.3 forecloses that by making expiry
 * mandatory — this file only fixes how long is too long.
 *
 * The 365-day ceiling matches the review cadence the approved baseline already
 * commits to: every one of the seven AWS-* baseline documents carries the same
 * Review Cycle field — "At least annually and upon material architectural,
 * regulatory, security, or service-model change." An exception that outlives
 * the annual review of the document set governing it would be reviewed by
 * nobody. NIST SP 800-37 Rev. 2's ongoing-authorization model rests on the
 * same principle: accepted risk is revisited on a defined cadence, not granted
 * once and forgotten.
 *
 * The 90-day default is deliberately far tighter than the ceiling. A default
 * is what gets used when nobody thinks about the number, so it should be the
 * cautious end of the range, and a quarter is the shortest period that still
 * survives one business planning cycle.
 *
 * WHY REVIEW COMES BEFORE EXPIRY. review_lead_days is the gap between the
 * review date and the expiry date: the acceptance must be looked at while it
 * is still valid, so a lapse is a decision rather than an accident. Thirty
 * days is a working month — enough to schedule the review, fix the issue, or
 * seek a fresh acceptance before the current one dies.
 *
 * @return array<string, int>
 */

declare(strict_types=1);

return [
    // The longest a single risk acceptance may run before it must be renewed
    // (SBR-5.3 "expiry"). See the header: bounded by the baseline's own
    // "at least annually" review cycle.
    'max_acceptance_days' => 365,

    // Applied when a caller names an approver, a rationale and a control but
    // no expiry date. A quarter — the cautious end of the range, because a
    // default is the value nobody deliberated over.
    'default_acceptance_days' => 90,

    // How far BEFORE expiry the mandatory review date falls (SBR-5.3 "review
    // date"). A working month, so the review happens while the acceptance is
    // still live.
    'review_lead_days' => 30,

    // Ceilings on caller-supplied free text, applied before storage. These are
    // not ergonomic limits: a remediation plan, a rationale or a comment is
    // human-written text that ends up rendered in a client report, and an
    // unbounded blob in a report is both a denial-of-service surface and a
    // place to hide content. The reporting layer escapes on output; this is
    // the size half of the same defence.
    'max_plan_chars' => 4000,
    'max_rationale_chars' => 4000,
    'max_control_chars' => 2000,
    'max_comment_chars' => 4000,
    'max_note_chars' => 2000,
];
