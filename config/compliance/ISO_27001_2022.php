<?php

/**
 * ISO/IEC 27001:2022 Annex A control mapping (P5-T7).
 *
 * Grounded in ISO/IEC 27001:2022 (93 controls across 4 themes: 5=Organizational,
 * 6=People, 7=Physical, 8=Technological). Maps shipped internal controls to real
 * Annex A clause IDs. Pinned with _meta (IsoSoc2MappingTest).
 *
 * @return array<string, mixed>
 */

declare(strict_types=1);

return [
    '_meta' => [
        'framework' => 'ISO-27001-2022',
        'published' => '2022-10',
        'source' => 'https://www.iso.org/standard/27001',
        'annex_a_themes' => ['5' => 'Organizational', '6' => 'People', '7' => 'Physical', '8' => 'Technological'],
    ],
    'SFR-AUTH-001' => ['ISO_27001_2022' => ['A.8.5']],    // Access control
    'SFR-SELF-001' => ['ISO_27001_2022' => ['A.8.20']],   // Networks security
    'SFR-SELF-003' => ['ISO_27001_2022' => ['A.8.10']],   // Information deletion (no egress of restricted)
    'AC-001'       => ['ISO_27001_2022' => ['A.8.5']],    // Tenant isolation = access control
    'AC-002'       => ['ISO_27001_2022' => ['A.8.20', 'A.5.23']], // Allowlists + cloud
    'AC-006'       => ['ISO_27001_2022' => ['A.5.23']],   // One control model = cloud security
    'SEC-005'      => ['ISO_27001_2022' => ['A.5.23', 'A.8.20']], // Deny-by-default
];
