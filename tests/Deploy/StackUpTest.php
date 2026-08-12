<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * P4-T4 — stack-up sizing selection (idempotent, safe arg parsing).
 * Bash-level: we don't bring a stack up in tests; we assert the script parses
 * --size / --deploy-config and selects a profile without crashing. Count-free:
 * assert on stdout keywords, never on counts/hashes (DocumentationFreshnessTest).
 */
final class StackUpTest extends TestCase
{
    private const SCRIPT = '/app/scripts/stack-up.sh';

    #[Test]
    public function test_dry_run_selects_small_profile(): void
    {
        $out = shell_exec("bash " . escapeshellarg(self::SCRIPT) . " --dry-run --size small 2>&1");
        self::assertIsString($out);
        self::assertStringContainsString('SIZE=small', $out);
        self::assertStringContainsString('DRY_RUN', $out);
    }

    #[Test]
    public function test_default_size_is_medium_when_unset(): void
    {
        $out = shell_exec("bash " . escapeshellarg(self::SCRIPT) . " --dry-run 2>&1");
        self::assertIsString($out);
        self::assertStringContainsString('SIZE=medium', $out);
    }

    #[Test]
    public function test_unknown_size_is_rejected(): void
    {
        $out = shell_exec("bash " . escapeshellarg(self::SCRIPT) . " --dry-run --size spaceship 2>&1");
        self::assertIsString($out);
        self::assertStringContainsString('INVALID_SIZE', $out);
    }
}
