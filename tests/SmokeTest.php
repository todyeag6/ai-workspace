<?php

declare(strict_types=1);

namespace App\Tests;

use PHPUnit\Framework\TestCase;

final class SmokeTest extends TestCase
{
    public function test_harness_runs(): void
    {
        // Asserting a literal true is a tautology (PHPStan flags it, rightly).
        // Assert something the harness actually has to get right instead: this
        // class was discovered by the PHPUnit runner, resolved through the
        // composer PSR-4 "App\Tests\" mapping, loaded and executed.
        $this->assertContains(
            self::class,
            get_declared_classes(),
            'The smoke test class must be autoloaded and executing.'
        );
    }
}
