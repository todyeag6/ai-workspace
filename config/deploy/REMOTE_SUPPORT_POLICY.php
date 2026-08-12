<?php

/**
 * Remote-Support Telemetry Policy — Aiwebscapes Local/Hybrid Toolkit (P4-T10).
 *
 * STATUS: PROPOSED — owner to ratify and SUPPLY the allowlisted Aiwebscapes
 * ingest endpoint. Telemetry is DISABLED by default (SEC-005 deny-by-default):
 * an opt-in, allowlisted exfil of health/version/exception counts ONLY — never
 * client data or leads (AC-001/002). Egress is restricted to `allowed_endpoints`
 * (FR-TOOL-003 allowlist, never a model-output-controlled URL).
 *
 * Pinned by tests/Deploy/RemoteSupportTest.php — unsourced change to `enabled`
 * or the allowlist fails CI. Flip `status` to RATIFIED + fill `allowed_endpoints`
 * only after owner sign-off.
 *
 * @return array<string,mixed>
 */

declare(strict_types=1);

return [
    'status' => 'PROPOSED',
    'config_version' => 'remote-support-2026-08-12',
    'enabled' => false,
    // Owner to fill: the allowlisted Aiwebscapes ingest endpoint(s).
    'allowed_endpoints' => [],
    // What may ever be sent (closed allowlist of keys; no client/lead data).
    'payload_keys' => ['health', 'version', 'exception_count'],
];
