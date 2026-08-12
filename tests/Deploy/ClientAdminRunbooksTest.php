<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * P4-T11 — Client-administrator runbooks cover the BR-9.1 / BR-9.2 ownership
 * record and the local/hybrid operations surface. Count-free, keyword-based
 * coverage (matches IncidentCoverageTest): proves the runbooks exist and name
 * the required responsibilities, without hardcoding mutable state.
 */
final class ClientAdminRunbooksTest extends TestCase
{
    private const DIR = __DIR__ . '/../../docs/client-admin';

    private function read(string $file): string
    {
        $path = self::DIR . '/' . $file;
        self::assertFileExists($path, 'Client-admin runbook missing: ' . $file);
        $text = file_get_contents($path);
        self::assertIsString($text);
        return $text;
    }

    #[Test]
    public function test_administration_runbook_covers_br91_ownership(): void
    {
        $text = $this->read('ADMINISTRATION.md');
        // BR-9.1 fields the client admin owns / must see.
        self::assertStringContainsString('data location', $text);
        self::assertStringContainsString('model location', $text);
        self::assertStringContainsString('administrator', $text);
        self::assertStringContainsString('support boundary', $text);
        self::assertStringContainsString('backup', $text);
        self::assertStringContainsString('update', $text);
        self::assertStringContainsString('exit', $text);
    }

    #[Test]
    public function test_administration_runbook_covers_br92_client_duties(): void
    {
        $text = $this->read('ADMINISTRATION.md');
        // BR-9.2 client-side duties.
        self::assertStringContainsString('physical security', $text);
        self::assertStringContainsString('endpoint', $text);
        self::assertStringContainsString('network', $text);
        self::assertStringContainsString('identity', $text);
        self::assertStringContainsString('patching', $text);
    }

    #[Test]
    public function test_runbook_references_the_derived_status_script_not_hardcoded_state(): void
    {
        $text = $this->read('ADMINISTRATION.md');
        self::assertStringContainsString('scripts/status.sh', $text);
    }

    #[Test]
    public function test_operation_runbook_documents_local_hybrid_services(): void
    {
        $text = $this->read('OPERATIONS.md');
        // The in-stack services delivered in Theme 3-4.
        self::assertStringContainsString('ollama', $text);
        self::assertStringContainsString('openviking', $text);
        self::assertStringContainsString('stack-up', $text);
        self::assertStringContainsString('app_net', $text);
        self::assertStringContainsString('scanner_net', $text);
    }

    #[Test]
    public function test_operation_runbook_documents_opt_in_remote_support(): void
    {
        $text = $this->read('OPERATIONS.md');
        self::assertStringContainsString('REMOTE_SUPPORT_POLICY', $text);
        self::assertStringContainsString('deny-by-default', $text);
    }

    #[Test]
    public function test_certification_checklist_exists(): void
    {
        $text = $this->read('CERTIFICATION.md');
        self::assertStringContainsString('BR-9.1', $text);
        self::assertStringContainsString('certification', $text);
    }
}
