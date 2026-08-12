<?php

/**
 * Remote-Support Telemetry Policy — Aiwebscapes Local/Hybrid Toolkit (P4-T10).
 *
 * STATUS: RATIFIED 2026-08-12 (owner sign-off on the policy POSTURE). Telemetry
 * remains DISABLED by default (SEC-005 deny-by-default): opt-in, allowlisted exfil
 * of health/version/exception counts ONLY — never client data or leads (AC-001/002).
 * Egress is restricted to `allowed_endpoints` (FR-TOOL-003 allowlist, never a
 * model-output-controlled URL).
 *
 * The `allowed_endpoints` list is intentionally EMPTY and `enabled` is false: the
 * owner supplies the real Aiwebscapes ingest endpoint at deploy time. Per
 * CISA/FBI/NSA *Secure-by-Design Alert* (2024-07-10) and SEC-005, a ratified
 * policy must ship secure-by-default — we do NOT pre-fill a placeholder endpoint,
 * which would either be a fabricated URL or silently enable egress. Enablement is a
 * deliberate, owner-authored edit to `allowed_endpoints` + `enabled`, caught by the
 * pinning test.
 *
 * Pinned by tests/Deploy/RemoteSupportTest.php — unsourced change to `enabled` or
 * the allowlist fails CI. Ratification raised the bar; it did not remove the pin.
 *
 * ---------------------------------------------------------------------------
 * EXTERNAL GROUNDING (per repo convention; same live publications as other policies)
 * ---------------------------------------------------------------------------
 * - NIST SP 800-53 Rev 5 — AC-17 (Remote Access), AU-13 (Monitoring of User Activity),
 *   SC-8 (Transmission Confidentiality/Integrity): remote support is a time-boxed,
 *   authorized, monitored channel carrying the minimum observable data.
 * - CISA/FBI/NSA *Secure-by-Design Alert* (2024-07-10): vendors must ship
 *   secure-by-default; telemetry is off unless explicitly enabled with a vetted endpoint.
 * - SEC-005 (this platform): deny-by-default for any egress path.
 *
 * @return array<string,mixed>
 */

declare(strict_types=1);

return [
    'status' => 'RATIFIED',
    'config_version' => 'remote-support-2026-08-12-ratified',
    'ratified_on' => '2026-08-12',
    'enabled' => false,
    // Owner to fill at deploy time: the allowlisted Aiwebscapes ingest endpoint(s).
    // Empty + disabled by default (secure-by-default); see header.
    'allowed_endpoints' => [],
    // What may ever be sent (closed allowlist of keys; no client/lead data).
    'payload_keys' => ['health', 'version', 'exception_count'],
];
