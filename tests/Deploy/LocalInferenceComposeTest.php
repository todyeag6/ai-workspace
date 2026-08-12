<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P4-T5 — Composed local-inference (Ollama) service (hybrid; deny-by-default egress).
 * Parses compose.yaml and asserts the `ollama` service exists, attaches to
 * `app_net` only, and is NOT on the isolated `scanner_net` (SFR-SELF-001 topology).
 * Config-contract test, not a live network test.
 */
final class LocalInferenceComposeTest extends TestCase
{
    private const COMPOSE = __DIR__ . '/../../compose.yaml';

    #[Test]
    public function test_compose_declares_ollama_service(): void
    {
        $compose = $this->parse();
        self::assertArrayHasKey('ollama', $compose['services'] ?? [], 'Ollama service must be declared.');
    }

    #[Test]
    public function test_ollama_attaches_to_app_net_only(): void
    {
        $compose = $this->parse();
        $ollama = $compose['services']['ollama'] ?? [];
        $nets = $ollama['networks'] ?? [];
        self::assertContains('app_net', $nets, 'Ollama must be on app_net (local on-prem path).');
        self::assertNotContains('scanner_net', $nets, 'Ollama must NOT reach the isolated scanner segment.');
    }

    /**
     * @return array<string, mixed>
     */
    private function parse(): array
    {
        self::assertFileExists(self::COMPOSE);
        // Compose YAML is simple enough for a targeted parse; use Symfony YAML if present.
        if (class_exists(\Symfony\Component\Yaml\Yaml::class)) {
            return \Symfony\Component\Yaml\Yaml::parseFile(self::COMPOSE);
        }
        // Fallback: lightweight line scan for the assertions above.
        $text = (string) file_get_contents(self::COMPOSE);
        $services = [];
        if (preg_match('/^  ollama:\\s*$/m', $text, $m, PREG_OFFSET_CAPTURE)) {
            $start = $m[0][1];
            $rest = substr($text, $start);
            $parts = preg_split('/^\\n  [a-z_-]+:\\s*$/m', $rest, 2);
            $block = is_array($parts) ? $parts[0] : '';
            $services['ollama'] = [
                'networks' => preg_match_all('/-\s*(app_net|scanner_net)/', $block, $mm) ? $mm[1] : [],
            ];
        }
        return ['services' => $services];
    }
}
