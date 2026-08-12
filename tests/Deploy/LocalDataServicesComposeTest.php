<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P4-T7 — Composed local data services (FR-DATA-001 at rest).
 * MySQL (relational) already in-stack; OpenViking (vector/knowledge) declared as
 * an in-stack service on app_net only. Config-contract test (no live network).
 */
final class LocalDataServicesComposeTest extends TestCase
{
    private const COMPOSE = __DIR__ . '/../../compose.yaml';

    #[Test]
    public function test_compose_declares_openviking_service(): void
    {
        $compose = $this->parse();
        self::assertArrayHasKey('openviking', $compose['services'] ?? [], 'OpenViking local data service must be declared.');
    }

    #[Test]
    public function test_openviking_attaches_to_app_net_only(): void
    {
        $compose = $this->parse();
        $nets = $compose['services']['openviking']['networks'] ?? [];
        self::assertContains('app_net', $nets, 'OpenViking must be on app_net.');
        self::assertNotContains('scanner_net', $nets, 'OpenViking must NOT reach the isolated scanner segment.');
    }

    #[Test]
    public function test_relational_db_present(): void
    {
        $compose = $this->parse();
        self::assertArrayHasKey('db', $compose['services'] ?? [], 'In-stack MySQL provides local relational data.');
    }

    /**
     * @return array<string, mixed>
     */
    private function parse(): array
    {
        self::assertFileExists(self::COMPOSE);
        if (class_exists(\Symfony\Component\Yaml\Yaml::class)) {
            return \Symfony\Component\Yaml\Yaml::parseFile(self::COMPOSE);
        }
        $text = file_get_contents(self::COMPOSE);
        $services = [];
        foreach (['openviking', 'db'] as $name) {
            if (preg_match('/^  ' . $name . ':\s*$/m', $text, $m, PREG_OFFSET_CAPTURE)) {
                $start = $m[0][1];
                $block = preg_split('/^\n  [a-z_-]+:\s*$/m', substr($text, $start), 2)[0];
                $services[$name] = [
                    'networks' => preg_match_all('/-\s*(app_net|scanner_net)/', $block, $mm) ? $mm[1] : [],
                ];
            }
        }
        return ['services' => $services];
    }
}
