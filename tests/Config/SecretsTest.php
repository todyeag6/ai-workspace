<?php

declare(strict_types=1);

namespace App\Tests\Config;

use App\Config\MissingSecretException;
use App\Config\Secrets;
use PHPUnit\Framework\TestCase;

/**
 * FR-CONF-001 / FR-CONF-002 / SEC-006.
 *
 * Secrets must never be hard-coded, and a missing required value must stop
 * the boot rather than silently degrade to an empty credential. These tests
 * pin the fail-closed contract.
 *
 * Deliberately extends PHPUnit's TestCase - not App\Tests\TestCase - because
 * nothing here touches the database; the suite stays fast and dependency-free.
 */
final class SecretsTest extends TestCase
{
    public function test_missing_required_secret_throws(): void
    {
        $secrets = new Secrets(['DB_DSN' => 'mysql:host=db']);

        $this->expectException(MissingSecretException::class);

        $secrets->require('APP_KEY');
    }

    public function test_validate_required_fails_closed(): void
    {
        $this->expectException(MissingSecretException::class);

        Secrets::validateRequired(['DB_DSN', 'APP_KEY', 'REDIS_DSN', 'AI_LOCAL_BASE_URL'], []);
    }

    public function test_present_secret_returned(): void
    {
        $this->assertSame('v', (new Secrets(['APP_KEY' => 'v']))->require('APP_KEY'));
    }

    /**
     * The happy path of the static guard: it must return quietly when every
     * key is present. Asserting on a value read back afterwards proves both
     * that no exception escaped and that the same env really did satisfy it.
     */
    public function test_validate_required_passes_when_all_present(): void
    {
        $env = ['A' => '1', 'B' => '2'];

        Secrets::validateRequired(['A', 'B'], $env);

        $this->assertSame('1', (new Secrets($env))->require('A'));
    }

    public function test_empty_string_secret_throws(): void
    {
        $secrets = new Secrets(['APP_KEY' => '']);

        $this->expectException(MissingSecretException::class);

        $secrets->require('APP_KEY');
    }

    /**
     * getenv() yields false - not null - for an unset variable, so a false
     * value must be treated exactly like an absent one.
     */
    public function test_false_value_throws(): void
    {
        $secrets = new Secrets(['APP_KEY' => false]);

        $this->expectException(MissingSecretException::class);

        $secrets->require('APP_KEY');
    }

    /**
     * An operator debugging a refused boot needs to know which key failed.
     * The key name is safe to print; a secret value never would be.
     */
    public function test_exception_message_names_the_key(): void
    {
        $secrets = new Secrets([]);

        $this->expectException(MissingSecretException::class);
        $this->expectExceptionMessage('APP_KEY');

        $secrets->require('APP_KEY');
    }
}
