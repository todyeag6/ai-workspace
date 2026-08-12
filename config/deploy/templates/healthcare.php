<?php
/**
 * Industry template: healthcare.
 * Medium profile; PHI-class data defaults to local with restricted-class refusal.
 * @return array<string,mixed>
 */
return [
    'hardware_profile' => 'medium',
    'policy_defaults' => [
        'deployment_model' => 'local',
        'data_residency' => 'local',
        'data_classification_default' => 'restricted',
    ],
    'sector_notes' => 'Healthcare: PHI treated as restricted (SFR-SELF-003 refuses cloud egress). Maps to HIPAA safeguards where the client operates in a regulated jurisdiction.',
];
