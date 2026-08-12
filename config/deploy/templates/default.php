<?php

/**
 * Industry template: default (generic SMB).
 * Composes a Phase-4 medium hardware tier with baseline policy defaults.
 * @return array<string,mixed>
 */

declare(strict_types=1);

return [
    'hardware_profile' => 'medium',
    'policy_defaults' => [
        'deployment_model' => 'hybrid',
        'data_residency' => 'local',
    ],
    'sector_notes' => 'Generic small/medium business. Local-sensitive inference on in-stack Ollama; non-restricted burst to cloud adapter under AC-006.',
];
