<?php

/**
 * P3-T5 Finding Engine — remediation-deadline (SLA) policy.
 *
 * SOURCE OF THE REQUIREMENT: SBR-5.1 (AWS-SBRD, 06 Defensive AI Security Agent
 * BRD) states that "critical and high findings shall generate CONFIGURED
 * alerts and remediation deadlines". SFR-FIND-001 then requires every finding
 * to carry an SLA.
 *
 * IMPORTANT (do not "fix" by hardcoding these into the engine): the approved
 * baseline specifies NO numeric deadlines anywhere. It says the deadlines are
 * *configured* — which makes the numbers a service-plan parameter, not a
 * requirement. Inventing hours/days inside FindingEngine would put unratified
 * numbers into a production gate and make them invisible to the person whose
 * contract they encode. They therefore live here: one auditable,
 * change-controlled file a ratifier edits without touching the engine, exactly
 * as config/eval/KPI_THRESHOLDS.php does for the BRD Table 4 measures.
 *
 * ---------------------------------------------------------------------------
 * EXTERNAL GROUNDING (reviewed 2026-08-10)
 * ---------------------------------------------------------------------------
 * The values below are aligned to the CURRENT federal standard. Two things
 * changed in 2026 that invalidate the older "14-day KEV" convention these
 * numbers would otherwise have inherited:
 *
 *   - CISA Binding Operational Directive 22-01 (the flat 14-day KEV deadline)
 *     and BOD 19-02 were BOTH REVOKED on 10 June 2026, superseded by
 *     BOD 26-04 "Prioritizing Security Updates Based on Risk". Citing a
 *     14-day KEV rule today cites a dead directive.
 *   - BOD 26-04 replaces flat CVSS-severity timelines with a graduated model
 *     over four binary signals (publicly exposed / in KEV / automatable by
 *     adversary / technical impact = total vs partial). Its Appendix A
 *     Table 1 maps the 16 combinations onto five tiers:
 *         3 days + mandatory forensic triage  (in KEV AND total control)
 *         3 days                              (highest-risk non-KEV combos)
 *         14 days                             (most KEV-listed vulns)
 *         60 days                             (lower-risk combos)
 *         fix on system upgrade               (no risk criteria met)
 *     BOD 26-04 also notes CISA defaults to a 60-day timeline when CVE
 *     metadata is unavailable, and treats exposure as YES when unknown —
 *     i.e. the standard itself fails closed on missing information.
 *
 * WHY THIS FILE STILL KEYS ON SEVERITY. Our Finding severity is a DERIVED
 * signal: FindingEngine::score() already folds evidence confidence into it,
 * and the scanner categories carry exposure context. Until the agent records
 * BOD 26-04's four signals as first-class per-finding fields, a severity key
 * is the honest approximation — and the mapping below is chosen so each tier
 * lands on a BOD 26-04 tier boundary rather than on invented round numbers.
 *
 * UPGRADE PATH (not baselined — raise a change request before building):
 * record the four signals per finding and select from Table 1 directly. That
 * needs exposure (knowable from our asset inventory) plus KEV / automatable /
 * technical-impact from a CVE feed such as CISA's Vulnrichment data.
 *
 * Each entry is the number of hours from a finding's FIRST sighting to its
 * remediation deadline. A null means "no deadline" — informational findings
 * carry no remediation clock, and inventing one would make every posture note
 * look overdue.
 *
 * The severity vocabulary matches App\SecurityAgent\Finding::SEVERITIES.
 *
 * @return array<string, int|null>
 */

declare(strict_types=1);

return [
    // 24h. Our `critical` means confirmed-exploitable with high-impact
    // control, i.e. BOD 26-04's "3 days + forensic triage" tier. We commit
    // TIGHTER than the federal ceiling: BOD 26-04 states its timelines are a
    // maximum ("Agencies with a lower tolerance for this risk may set shorter
    // timelines"), and a commercial engagement that found a live critical
    // should not sit on it for three days. Also consistent with PCI DSS v4.0.1
    // req. 6.3.3 treating critical patching as the most urgent class.
    'critical' => 24,

    // 72h = the BOD 26-04 three-day tier exactly. Applies to high-risk
    // findings that are not yet confirmed-exploited-with-total-control.
    'high' => 72,

    // 14 days = 336h. The BOD 26-04 "most KEV-listed vulnerabilities" tier,
    // and the same two-week figure the revoked BOD 22-01 used as its flat KEV
    // deadline — retained here because it remains a live tier in the current
    // directive, not because of the old rule.
    'medium' => 336,

    // 60 days = 1440h. The BOD 26-04 lower-risk tier and its documented
    // default when CVE metadata is unavailable. NOTE: this REPLACES an earlier
    // proposed 90 days (2160h), which came from the FedRAMP low-severity
    // convention rather than the current directive; 60 days is both the more
    // defensible citation and the tighter commitment.
    'low' => 1440,

    // No remediation clock: an informational item is posture, not a defect.
    // This is the analogue of BOD 26-04's "fix on system upgrade" deferral
    // tier, which exists precisely so low-signal items do not consume the
    // remediation budget (CISA found >60% of instances qualify for deferral).
    'informational' => null,
];
