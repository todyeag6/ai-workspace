<?php

/**
 * NIST CSF 2.0 control mapping (P5-T6).
 *
 * Grounded in NIST Cybersecurity Framework 2.0 (published 2024-02, six Functions:
 * Govern GV, Identify ID, Protect PR, Detect DE, Respond RS, Recover RC). Maps the
 * platform's shipped internal controls (SFR/AC/SEC) to real CSF 2.0 category IDs.
 * Pinned with _meta so an unsourced edit fails NistCsfMappingTest.
 *
 * @return array<string, mixed>
 */

declare(strict_types=1);

return [
    '_meta' => [
        'framework' => 'NIST-CSF-2.0',
        'published' => '2024-02',
        'source' => 'https://www.nist.gov/cyberframework',
    ],
    'SFR-AUTH-001' => ['NIST_CSF_2_0' => ['PR.AA-01']],   // Identity management, authentication
    'SFR-SELF-001' => ['NIST_CSF_2_0' => ['PR.IR-01']],  // Protected technology asset management (segmentation)
    'SFR-SELF-003' => ['NIST_CSF_2_0' => ['PR.DS-01']],   // Data protection at rest/in transit
    'AC-001'       => ['NIST_CSF_2_0' => ['PR.AA-01']],   // Tenant isolation = access control
    'AC-002'       => ['NIST_CSF_2_0' => ['PR.PS-01']],   // Allowlists = policy enforcement
    'AC-006'       => ['NIST_CSF_2_0' => ['GV.RM-01']],   // One control model = governance/risk
    'SEC-005'      => ['NIST_CSF_2_0' => ['PR.PS-01']],   // Deny-by-default = protective policy
];
