<?php

declare(strict_types=1);

namespace App\Tests\SecurityAgent;

use App\Audit\AuditLogger;
use App\SecurityAgent\IncidentSignal;
use App\SecurityAgent\SafeScannerInvoker;
use App\SecurityAgent\TargetRefused;
use App\Tests\TestCase;
use PDO;

/**
 * SFR-SELF-006 - incident procedures coverage.
 *
 * Two things are proven here:
 *   1. The runbook (docs/INCIDENT_RESPONSE.md) actually names all four
 *      SFR-SELF-006 scenarios and cites the current official references
 *      (NIST SP 800-61r2 + OWASP LLM 2025). The assertion is keyword-by-name,
 *      NOT a hardcoded count/hash, because tests/Docs/DocumentationFreshnessTest
 *      forbids stale counts in the suite.
 *   2. A scanner refusal produces a MEASURABLE, audited incident event via
 *      IncidentSignal (NIST AI RMF 1.0 Measure/Manage). The event's object_id
 *      is a bounded reason code (survives AuditLogger redaction), asserted
 *      directly rather than via free-text detail.
 *
 * The falsification probe (c) proves the signal is the emitter: without it
 * wired, a refusal still happens but NO audit row is created.
 *
 * © AI WebScapes 2026
 */
final class IncidentCoverageTest extends TestCase
{
    private function runbookPath(): string
    {
        $path = dirname(__DIR__, 2) . '/docs/INCIDENT_RESPONSE.md';
        self::assertFileExists($path, 'Runbook must exist.');

        return $path;
    }

    public function test_runbook_covers_self006_scenarios_by_name(): void
    {
        $text = (string) file_get_contents($this->runbookPath());

        // SFR-SELF-006's four required scenarios, named verbatim from the FRD.
        self::assertStringContainsString('accidental out-of-scope traffic', $text);
        self::assertStringContainsString('service degradation', $text);
        self::assertStringContainsString('credential exposure', $text);
        self::assertStringContainsString('evidence leakage', $text);

        // The mapping cites the current official sources (most recent editions).
        self::assertStringContainsString('NIST SP 800-61r2', $text);
        self::assertStringContainsString('OWASP', $text);
        self::assertStringContainsString('Top 10 for LLM', $text);
    }

    public function test_refusal_emits_audited_incident_signal_with_bounded_object_id(): void
    {
        $signal = new IncidentSignal(new AuditLogger($this->pdo));
        $before = $this->countSignalRows('self005:cmd-injection');

        $signal->scanRefused(1, 'self005:cmd-injection', 'denied', ['tool' => 'nmap']);

        $after = $this->countSignalRows('self005:cmd-injection');
        self::assertSame($before + 1, $after, 'Exactly one bounded-object_id audit row is written.');

        // The row is queryable and its object_id is the bounded reason code,
        // never the (hostile) target string.
        $row = $this->fetchSignalRow('self005:cmd-injection');
        self::assertIsArray($row);
        self::assertSame('scanner.scan_refused', $row['action']);
        self::assertSame('denied', $row['outcome']);
        self::assertSame('security_agent', $row['source']);
    }

    /**
     * FALSIFICATION PROBE: without the signal wired into the invoker, a refusal
     * still occurs (the guard decides), but NO audit row is created by the
     * signal. This proves the recorded incident event depends on IncidentSignal,
     * not on some other emitter - disabling it removes the evidence.
     */
    public function test_falsification_probe_signal_is_the_emitter(): void
    {
        $policy = require dirname(__DIR__, 2) . '/config/security/SCANNER_TARGET_POLICY.php';
        // Invoker constructed WITHOUT an IncidentSignal.
        $invoker = new SafeScannerInvoker($policy);

        $before = $this->countSignalRows('self005:network-pivot');

        $threw = false;
        try {
            // A target the sanitizer genuinely refuses (cloud metadata /
            // network pivot) - the refusal must still occur without a signal.
            $invoker->run('nmap', 'https://169.254.169.254/latest/meta-data/');
        } catch (TargetRefused $e) {
            $threw = true;
        }
        self::assertTrue($threw, 'The guard still refuses the target without a signal.');

        $after = $this->countSignalRows('self005:network-pivot');
        self::assertSame($before, $after, 'Without IncidentSignal wired, no audit row is created - the signal is the emitter.');
    }

    private function countSignalRows(string $objectId): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM audit_events WHERE object_id = :oid'
        );
        $stmt->bindValue('oid', $objectId);
        $stmt->execute();

        return (int) $stmt->fetchColumn();
    }

    /**
     * @return array<string,string>|null
     */
    private function fetchSignalRow(string $objectId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT action, outcome, source FROM audit_events WHERE object_id = :oid LIMIT 1'
        );
        $stmt->bindValue('oid', $objectId);
        $stmt->execute();

        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }
}
