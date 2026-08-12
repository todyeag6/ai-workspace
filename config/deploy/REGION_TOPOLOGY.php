<?php

/**
 * Region topology policy — Aiwebscapes Local/Hybrid Toolkit (P5-T9, BRD §16 #5).
 *
 * STATUS: PROPOSED. Multi-region is OPT-IN and "where justified". The default is a
 * single region and multi-region is DISABLED. Enabling it requires `justified: true`
 * and a populated `residency_allowlist`, after a documented business justification.
 * A `local` deployment never replicates across regions (SEC-005 deny-by-default,
 * FR-DATA-001). Flip to RATIFIED only after owner sign-off; update
 * MultiRegionTopologyTest in the same commit.
 *
 * @return array<string,mixed>
 */

declare(strict_types=1);

return [
    'status' => 'PROPOSED',
    'config_version' => 'region-topology-2026-08-12',
    'default' => [
        'enabled' => false,
        'regions' => ['us-east'],
        'justified' => false,
        'residency_allowlist' => ['us-east'],
        'deployment_model' => 'hybrid',
    ],
];
