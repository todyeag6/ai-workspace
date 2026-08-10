<?php

/**
 * P3-T8 Reporting — report windows, retention hints and disposition labels.
 *
 * SOURCE OF THE REQUIREMENT: FRD section 2 gives Reporting the job
 * "Executive, technical, compliance mapping, trend, acceptance and retest
 * reports", and the governing rules are:
 *
 *   SFR-REPORT-001 [Must] Reports shall clearly distinguish confirmed,
 *                  suspected, informational, accepted, remediated, and
 *                  not-retested items.
 *   SFR-AUTH-003   [Must] Credentials shall be stored as scoped secrets and
 *                  never included in reports or logs.
 *   SFR-AUD-001    [Must] All scope, scan, finding, severity, assignment,
 *                  exception, export, and retest changes shall be audited.
 *
 * And FRD section 7's two acceptance tests, which are this component's litmus:
 *
 *   Report redaction → "Secrets and session tokens are absent from normal
 *                       report output."
 *   Cross tenant     → "No finding/evidence/report access across tenant."
 *
 * IMPORTANT (do not "fix" by hardcoding these into the component): exactly as
 * with config/security/FINDING_SLA.php and REMEDIATION_POLICY.php, the
 * approved baseline specifies NO numeric windows here. The BRD asks for a
 * "trend and posture report for recurring service" (section 6 Deliverables)
 * but names no lookback period, and nothing in the baseline says how many
 * periods a trend must span. Those numbers are a service-plan parameter, not a
 * requirement, and they live in this one auditable, change-controlled file
 * that a ratifier edits without touching SecurityReportBuilder.
 *
 * STATUS: RATIFIED 2026-08-10 by the platform owner. The values below are now
 * approved policy, not proposed defaults. tests/SecurityAgent/
 * SecurityReportingTest.php::test_shipped_report_policy_pins_its_contract_terms
 * REMAINS IN FORCE and pins these values, so changing one without updating the
 * test — and therefore without a reviewer seeing it — fails CI. Ratification
 * raises the bar on an edit; it does not remove it.
 *
 * ---------------------------------------------------------------------------
 * EXTERNAL GROUNDING (reviewed 2026-08-10 against the live publications)
 * ---------------------------------------------------------------------------
 * - NIST SP 800-137, "Information Security Continuous Monitoring (ISCM) for
 *   Federal Information Systems and Organizations" (Final, September 2011;
 *   confirmed not withdrawn and not superseded). ISCM is built on a defined
 *   monitoring FREQUENCY per security control, with status reported against
 *   that cadence — which is why a trend report needs a declared window rather
 *   than "everything we have". Assessed further by SP 800-137A (Final, May
 *   2020).
 * - NIST SP 800-115, "Technical Guide to Information Security Testing and
 *   Assessment" (Final, September 2008; supersedes SP 800-42; confirmed not
 *   withdrawn). Its section 8 is the reporting-and-remediation phase this
 *   component implements: findings are reported alongside their mitigation
 *   state, not as a bare list.
 * - OWASP ASVS 5.0, V16.2.5: when logging sensitive data the application
 *   enforces handling based on the data's protection level — credentials must
 *   not be emitted at all, while session tokens may appear only hashed or
 *   masked. A report is an export of the same class of data, so the redaction
 *   gate treats a secret or session-token hit as fatal rather than
 *   printable. V16.5.3 (fail securely, "preventing fail-open conditions") is
 *   why the gate REFUSES the report instead of emitting a degraded one.
 *
 * The quarterly default below matches the baseline's own recurring-service
 * rhythm (06 BRD section 6, "trend and posture report for recurring service")
 * and the "at least annually" review cycle already cited by
 * REMEDIATION_POLICY.php: four quarterly windows make a year of posture
 * visible in one report.
 *
 * © AI WebScapes 2026
 */

declare(strict_types=1);

return [
    // How far back a trend/posture report looks by default, in days. A quarter
    // — the shortest window over which a remediation programme's direction is
    // legible rather than noise, and the cadence a recurring service bills on.
    'trend_lookback_days' => 90,

    // How many consecutive lookback windows a trend report compares. Four
    // quarters = one year of posture, matching the annual review cycle.
    // Two would show a direction; four shows whether it held.
    'trend_periods' => 4,

    // A report may not silently truncate its own evidence. When a report body
    // would exceed this many rows the builder refuses rather than emitting a
    // partial register that reads as complete — the same fail-closed reasoning
    // as the risk-acceptance ceiling in REMEDIATION_POLICY.php. Generous
    // enough that no honest engagement hits it.
    'max_report_rows' => 5000,

    // Ceiling on any single caller-supplied report title, applied before
    // rendering. The assembler escapes on output; this is the size half of the
    // same defence (mirrors REMEDIATION_POLICY.php's text ceilings).
    'max_title_chars' => 200,
];
