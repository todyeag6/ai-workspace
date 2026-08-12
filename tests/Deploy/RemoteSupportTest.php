<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\Deploy\RemoteSupport;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P4-T10 — Opt-in remote-support telemetry (SEC-005 deny-by-default, FR-TOOL-003 egress allowlist).
 * Telemetry is DISABLED by default; enabled only when policy enabled=true AND an
 * allowlisted endpoint. Payload carries health/version/exception counts ONLY —
 * never client data or leads (AC-001/002).
 */
final class RemoteSupportTest extends TestCase
{
    private const POLICY_OFF = __DIR__ . '/../../config/deploy/REMOTE_SUPPORT_POLICY.php';
    private const POLICY_ON = __DIR__ . '/../../config/deploy/REMOTE_SUPPORT_POLICY.enabled.php';

    #[Test]
    public function test_telemetry_refused_when_policy_disabled(): void
    {
        self::assertFileExists(self::POLICY_OFF);
        $policy = require self::POLICY_OFF;
        $support = new RemoteSupport($policy, ['https://support.aiwebscapes.example/ingest']);
        self::assertFalse(
            $support->mayTransmit(),
            'Default-off policy must refuse telemetry (SEC-005 deny-by-default).'
        );
    }

    #[Test]
    public function test_telemetry_allowed_only_to_allowlisted_endpoint(): void
    {
        self::assertFileExists(self::POLICY_ON);
        $policy = require self::POLICY_ON;
        $support = new RemoteSupport($policy, ['https://support.aiwebscapes.example/ingest']);
        self::assertTrue($support->mayTransmit());
        self::assertSame(
            'https://support.aiwebscapes.example/ingest',
            $support->endpoint()
        );
    }

    #[Test]
    public function test_telemetry_rejected_when_endpoint_not_allowlisted(): void
    {
        self::assertFileExists(self::POLICY_ON);
        $policy = require self::POLICY_ON;
        $support = new RemoteSupport($policy, []); // empty allowlist
        self::assertFalse(
            $support->mayTransmit(),
            'Enabled policy with no allowlisted endpoint must still refuse (FR-TOOL-003).'
        );
    }

    #[Test]
    public function test_telemetry_payload_carries_no_client_data(): void
    {
        $policy = require self::POLICY_ON;
        $support = new RemoteSupport($policy, ['https://support.aiwebscapes.example/ingest']);
        $payload = $support->buildPayload(
            healthStatus: ['db' => ['ok' => true]],
            version: '2026-08-12',
            exceptionCount: 0
        );
        // Assert the payload is a closed, known shape with no row/lead data.
        self::assertArrayHasKey('health', $payload);
        self::assertArrayHasKey('version', $payload);
        self::assertArrayHasKey('exception_count', $payload);
        self::assertArrayNotHasKey('leads', $payload);
        self::assertArrayNotHasKey('tenants', $payload);
        self::assertArrayNotHasKey('client_data', $payload);
    }
}
