<?php

/**
 * SOC 2 Trust Services Criteria (TSC) mapping (P5-T7).
 *
 * Grounded in AICPA 2017 Trust Services Criteria with revised Points of Focus
 * (2022). Five criteria: Security (CC, required/common), Availability (A),
 * Processing Integrity (PI), Confidentiality (C), Privacy (P). Maps shipped
 * internal controls to real TSC clause IDs. Pinned with _meta (IsoSoc2MappingTest).
 *
 * @return array<string, mixed>
 */

declare(strict_types=1);

return [
    '_meta' => [
        'framework' => 'SOC2-TSC-2017-2022',
        'published' => '2022-rev',
        'source' => 'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022',
        'criteria' => ['CC' => 'Security', 'A' => 'Availability', 'PI' => 'Processing Integrity', 'C' => 'Confidentiality', 'P' => 'Privacy'],
    ],
    'SFR-AUTH-001' => ['SOC2_TSC' => ['CC6.1', 'CC6.2']],  // Logical access security
    'SFR-SELF-001' => ['SOC2_TSC' => ['CC6.6', 'CC6.7']],  // Boundary protection
    'SFR-SELF-003' => ['SOC2_TSC' => ['C1.1', 'C1.2']],    // Confidentiality of data
    'AC-001'       => ['SOC2_TSC' => ['CC6.1']],           // Tenant isolation
    'AC-002'       => ['SOC2_TSC' => ['CC6.6']],           // Restriction via allowlists
    'AC-006'       => ['SOC2_TSC' => ['CC6.1']],           // Consistent access model
    'SEC-005'      => ['SOC2_TSC' => ['CC6.1', 'CC6.6']],  // Deny-by-default access
];
