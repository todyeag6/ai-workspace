<?php

declare(strict_types=1);

namespace App\Tests\Identity;

use App\Identity\PasswordHasher;
use PHPUnit\Framework\TestCase;

/**
 * FR-IDENT-002: password hashing with argon2id and rehash-on-cost-upgrade.
 *
 * Deliberately extends PHPUnit's own TestCase - NOT App\Tests\TestCase - because
 * password hashing needs NO database: App\Tests\TestCase opens a MySQL connection
 * and re-applies every migration on every test, which is pure waste here and would
 * couple this test to the shared infra a sibling agent is actively changing.
 */
final class PasswordHasherTest extends TestCase
{
    public function test_hash_verifies(): void
    {
        $h = new PasswordHasher();
        $this->assertTrue($h->verify('s3cret', $h->hash('s3cret')));
    }

    public function test_uses_argon2id(): void
    {
        $this->assertStringStartsWith('$argon2id$', (new PasswordHasher())->hash('x'));
    }

    public function test_needs_rehash_on_cost_upgrade(): void
    {
        $weak = (new PasswordHasher(['memory_cost' => 8192]))->hash('x');
        $this->assertTrue((new PasswordHasher(['memory_cost' => 65536]))->needsRehash($weak));
    }

    public function test_wrong_password_fails_verification(): void
    {
        $h = new PasswordHasher();
        $hash = $h->hash('correct-horse');
        $this->assertFalse($h->verify('battery-staple', $hash));
    }

    public function test_current_options_do_not_need_rehash(): void
    {
        $h = new PasswordHasher();
        $hash = $h->hash('x');
        $this->assertFalse($h->needsRehash($hash));
    }

    public function test_verify_returns_false_on_malformed_hash(): void
    {
        $h = new PasswordHasher();
        $this->assertFalse($h->verify('anything', ''));
        $this->assertFalse($h->verify('anything', 'not-a-valid-hash'));
    }
}
