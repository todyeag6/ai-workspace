<?php
/**
 * Industry template: legal.
 * Data residency is explicit and local (FR-DATA-001 posture for privileged client data).
 * @return array<string,mixed>
 */
return [
    'hardware_profile' => 'small',
    'policy_defaults' => [
        'deployment_model' => 'local',
        'data_residency' => 'local',
        'allow_cloud_burst' => false,
    ],
    'sector_notes' => 'Legal: privileged matter data stays on-prem. No cloud burst (BR-9.2 + FR-DATA-001). Client owns endpoint, patching, backup.',
];
