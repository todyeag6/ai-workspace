<?php

/**
 * Industry template: finance.
 * Large profile for higher density / on-demand model capacity.
 * @return array<string,mixed>
 */

declare(strict_types=1);

return [
    'hardware_profile' => 'large',
    'policy_defaults' => [
        'deployment_model' => 'hybrid',
        'data_residency' => 'local',
        'allow_cloud_burst' => true,
    ],
    'sector_notes' => 'Finance: higher tenant density; sensitive inference local, large/burst models via cloud adapter under AC-006. Maps to PCI-DSS scope where cardholder data is in scope (owner to confirm regimes).',
];
