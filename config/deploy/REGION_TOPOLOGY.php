<?php

/**
 * Region topology policy — Aiwebscapes Local/Hybrid Toolkit (P5-T9, BRD §16 #5).
 *
 * STATUS: RATIFIED (owner sign-off 2026-10-14). Multi-region is OPT-IN and
 * "where justified". The default is a single region and multi-region is
 * DISABLED. Enabling it requires `justified: true` and a populated
 * `residency_allowlist`, after a documented business justification.
 * A `local` deployment never replicates across regions (SEC-005 deny-by-default,
 * FR-DATA-001).
 *
 * Data-residency justification (2026-10-14): The platform serves US and EU
 * clients. Multi-region replication is approved for hybrid deployments only
 * (cloud-side redundancy), never for local/on-prem deployments. Approved
 * residency regions: us-east, us-west, eu-west. No PHI is collected or stored
 * (HIPAA out of scope per owner decision 2026-10-14).
 *
 * @return array<string,mixed>
 */

declare(strict_types=1);

return [
    'status' => 'RATIFIED',
    'config_version' => 'region-topology-2026-10-14',
    'ratified_at' => '2026-10-14',
    'ratified_by' => 'owner',
    'data_residency_justification' => 'US + EU clients; hybrid deployments may replicate to approved regions for cloud-side redundancy. Local/on-prem deployments never replicate (FR-DATA-001). No PHI collected or stored.',
    'default' => [
        'enabled' => false,
        'regions' => ['us-east'],
        'justified' => false,
        'residency_allowlist' => ['us-east', 'us-west', 'eu-west'],
        'deployment_model' => 'hybrid',
    ],
];
