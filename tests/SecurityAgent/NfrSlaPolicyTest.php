<?php

declare(strict_types=1);

namespace App\Tests\SecurityAgent;

use PHPUnit\Framework\TestCase;

/**
 * NFR Table 5 — Service Levels / Performance Budgets policy pinning test.
 *
 * Sourced to NIST SP 800-53 Rev 5 SC-5/SC-6/CP-10/SI-13, OWASP ASVS 5.0
 * V14.3, and Core Web Vitals INP (2024). The pinning test asserts the
 * PROPOSED status and the agreed numeric budgets; an unsourced value change
 * fails CI (the numbers are the contract, not prose).
 */
class NfrSlaPolicyTest extends TestCase
{
    /**
     * @return array<string, mixed>
     */
    private function policy(): array
    {
        $loaded = require dirname(__DIR__, 2) . '/config/security/NFR_SLA_POLICY.php';

        return is_array($loaded) ? $loaded : [];
    }

    public function test_shipped_nfr_sla_policy_pins_its_contract_terms(): void
    {
        $policy = $this->policy();

        self::assertSame('RATIFIED', $policy['status'] ?? null, 'Policy is ratified; an unsourced value change must still fail CI.');
        self::assertSame(99.9, $policy['availability']['monthly_uptime_percent']);
        self::assertSame(43, $policy['availability']['max_monthly_downtime_minutes']);
        self::assertTrue($policy['availability']['graceful_degradation_required']);
        self::assertSame(200, $policy['dashboard_interactivity']['inp_budget_ms']);
        self::assertSame(300, $policy['scanner_tasks']['single_scan_timeout_seconds']);
        self::assertSame(4, $policy['scanner_tasks']['max_concurrent_scans_per_tenant']);
        self::assertSame(4, $policy['recovery']['rto_hours']);
        self::assertSame(1, $policy['recovery']['rpo_hours']);
        self::assertSame(168, $policy['security_process_slas']['patch_target_hours']);
        self::assertSame(4, $policy['security_process_slas']['incident_response_target_hours']);
        self::assertNotEmpty($policy['source_reference']);
    }
}
