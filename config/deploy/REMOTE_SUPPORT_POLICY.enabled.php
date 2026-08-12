<?php

/**
 * Remote-Support Telemetry Policy — ENABLED example (P4-T10 test fixture only).
 *
 * NOT shipped as the active policy. This file exists so RemoteSupportTest can
 * exercise the enabled path against a real ratifiable-shaped policy. The actual
 * production policy (REMOTE_SUPPORT_POLICY.php) stays PROPOSED / default-off
 * until the owner ratifies it and supplies the allowlisted endpoint.
 *
 * @return array<string,mixed>
 */

declare(strict_types=1);

return [
    'status' => 'PROPOSED',
    'config_version' => 'remote-support-2026-08-12',
    'enabled' => true,
    'allowed_endpoints' => ['https://support.aiwebscapes.example/ingest'],
    'payload_keys' => ['health', 'version', 'exception_count'],
];
