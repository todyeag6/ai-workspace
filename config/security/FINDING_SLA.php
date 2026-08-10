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
    // PROPOSED 24h — owner to ratify. SBR-5.1 names critical explicitly.
    'critical' => 24,
    // PROPOSED 72h — owner to ratify. SBR-5.1 names high explicitly.
    'high' => 72,
    // PROPOSED 14 days — owner to ratify. Not named by SBR-5.1; a deadline is
    // still carried so "mean time to remediate" (BRD section 7) is measurable.
    'medium' => 336,
    // PROPOSED 90 days — owner to ratify.
    'low' => 2160,
    // No remediation clock: an informational item is posture, not a defect.
    'informational' => null,
];
