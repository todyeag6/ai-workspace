<?php

/**
 * Hardware Sizing Profiles — Aiwebscapes Local/Hybrid Toolkit (BRD Phase 4 #1).
 *
 * STATUS: RATIFIED 2026-08-12 (owner sign-off). These are committed SMB appliance
 * tiers, not measured guarantees. BR-9.2 requires that local deployment NOT be
 * represented as automatically more secure: the client owns physical, endpoint,
 * network, identity, patching, and backup responsibilities, summarized per tier in
 * `notes`. Do not over-promise.
 *
 * Pinned by tests/Deploy/HardwareSizingTest.php — an unsourced change to any
 * contract term fails CI. Ratification raised the bar on an edit; it did not
 * remove the pin.
 *
 * ---------------------------------------------------------------------------
 * EXTERNAL GROUNDING (per repo convention, same live publications as
 * config/security/SCAN_SCHEDULE_POLICY.php and FINDING_SLA.php)
 * ---------------------------------------------------------------------------
 * - NIST SP 800-53 Rev 5 (Dec 2020, current catalog) — CM-7 (Least Functionality /
 *   baseline configuration) frames the minimum_supported floor; RA-5 (Vulnerability
 *   Monitoring and Scanning) and PL-2 (System Security Plan) frame sizing as a
 *   documented, change-controlled baseline rather than an ad-hoc guess.
 * - CISA *Binding Operational Directive 26-04* (2026-06-10) tier boundaries are the
 *   basis already used by FINDING_SLA; these tiers sit inside those reassessment
 *   windows so a sized host can meet its SLA.
 * - CISA Secure-by-Design / Shifting the Balance (2023-2024) — default-secure
 *   posture: small tier is local-only with no cloud burst, matching "secure by
 *   default" rather than "secure if configured."
 *
 * ---------------------------------------------------------------------------
 * WHY THESE NUMBERS
 * ---------------------------------------------------------------------------
 * - small 2vCPU/4GB/40GB, 1 tenant, local-only: the floor a real SMB appliance
 *   can sustain; no cloud burst (BR-9.2 clean separation).
 * - medium 4/8/80, 5 tenants, hybrid-ready: sensitive inference local; large/burst
 *   models may use the cloud adapter under AC-006.
 * - large 8/16/160, 20 tenants, on-demand gemma4: highest density; client owns
 *   physical + backup + update (BR-9.1).
 * - minimum_supported mirrors `small` so the floor is the smallest supported unit.
 *
 * @return array<string,mixed>
 */

declare(strict_types=1);

return [
    'status' => 'RATIFIED',
    'config_version' => 'hw-sizing-2026-08-12-ratified',
    'ratified_on' => '2026-08-12',

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
