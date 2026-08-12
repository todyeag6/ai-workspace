<?php

/**
 * Hardware Sizing Profiles — Aiwebscapes Local/Hybrid Toolkit (BRD Phase 4 #1).
 *
 * STATUS: PROPOSED — owner to ratify the tier numbers against real SMB targets.
 * These are PROPOSED defaults, not measured commitments. BR-9.2 requires that
 * local deployment NOT be represented as automatically more secure: the client
 * owns physical, endpoint, network, identity, patching, and backup
 * responsibilities, summarized per tier in `notes`. Do not over-promise.
 *
 * Pinned by tests/Deploy/HardwareSizingTest.php — an unsourced change to any
 * contract term fails CI. Flip `status` to RATIFIED only after owner sign-off;
 * the pinning test must be updated in the same commit.
 *
 * @return array<string,mixed>
 */

declare(strict_types=1);

return [
    'status' => 'PROPOSED',
    'config_version' => 'hw-sizing-2026-08-12',

    // SMB appliance tiers. `ollama_models` lists the models that FIT this tier
    // under the owner's local-model policy (single-resident hermes3:8b always-on;
    // gemma4 on-demand only). `max_tenants` bounds multi-tenant density.
    'profiles' => [
        'small' => [
            'cpu_cores' => 2,
            'ram_gb' => 4,
            'disk_gb' => 40,
            'ollama_models' => ['hermes3:8b'],
            'max_tenants' => 1,
            'notes' => 'Local-only. Client owns endpoint hardening, patching, and backup. No burst to cloud.',
        ],
        'medium' => [
            'cpu_cores' => 4,
            'ram_gb' => 8,
            'disk_gb' => 80,
            'ollama_models' => ['hermes3:8b', 'qwen3:4b'],
            'max_tenants' => 5,
            'notes' => 'Hybrid-ready. Sensitive inference local; large/burst models may use the cloud adapter under AC-006. Client owns network + identity.',
        ],
        'large' => [
            'cpu_cores' => 8,
            'ram_gb' => 16,
            'disk_gb' => 160,
            'ollama_models' => ['hermes3:8b', 'qwen3:4b', 'gemma4:12b'],
            'max_tenants' => 20,
            'notes' => 'Hybrid-ready, on-demand gemma4. Client owns physical security + backup owner + update owner (BR-9.1).',
        ],
    ],

    // A host under these minimums is not a supported deployment target.
    'minimum_supported' => [
        'cpu_cores' => 2,
        'ram_gb' => 4,
        'disk_gb' => 40,
    ],
];
