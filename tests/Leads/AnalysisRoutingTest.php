<?php

declare(strict_types=1);

namespace App\Tests\Leads;

use App\Leads\LeadService;
use App\Security\RateLimiter;
use App\Tests\TestCase;
use PDO;
use Predis\Client;

/**
 * Duplicates, AI analysis and deterministic routing: LFR-DUP-001,
 * LFR-AI-001/002/003, LFR-ROUTE-001 and LBR-5.5.
 *
 * These tests exist to pin down the four guarantees that decide how much the
 * model is allowed to do:
 *
 *   LFR-DUP-001  a repeat enquiry is LINKED, never merged over the original.
 *                The first lead is evidence of what was actually sent, so the
 *                second submission adds an interaction and a duplicate link
 *                and leaves the first row byte-for-byte alone. Re-analysis
 *                likewise APPENDS a new version rather than updating the
 *                previous verdict.
 *   LFR-ROUTE-001 the business rule decides the owner, the model only
 *                suggests. A test that let the AI win here would be a test
 *                that documented AI autonomy over routing.
 *   LFR-AI-002   the request handed to the model carries no direct
 *                identifiers: an SSN in the lead never reaches the payload.
 *   LFR-AI-003   low confidence goes to a HUMAN ('Review'), not to an
 *                automatic action.
 *   LFR-AI-001   the analysis carries the full agreed schema, so consumers
 *                never have to guess which keys a model happened to emit.
 *
 * No model is called from this suite: analyse() is fed a literal array
 * standing in for whatever a model returned.
 *
 * © AI WebScapes 2026
 */
final class AnalysisRoutingTest extends TestCase
{
    private const TENANT_ID = '1';

    private const MAX_REQUESTS = 100;

    /** LFR-AI-001: the agreed analysis schema, in full. */
    private const SCHEMA_FIELDS = [
        'summary',
        'intent',
        'category',
        'urgency',
        'next_step',
        'risk_flags',
        'confidence',
        'rationale',
    ];

    private LeadService $service;

    private Client $redis;

    private string $bucket;

    protected function setUp(): void
    {
        parent::setUp();

        $this->redis = new Client(['host' => 'redis', 'port' => 6379]);
        $this->bucket = 'pub:leads:analysis:' . bin2hex(random_bytes(6));

        $this->service = new LeadService(
            $this->pdo,
            new RateLimiter($this->redis, $this->bucket, self::MAX_REQUESTS, 60),
            null
        );
    }

    protected function tearDown(): void
    {
        /** @var list<string> $keys */
        $keys = $this->redis->keys('ratelimit:' . $this->bucket . ':*');
        if ($keys !== []) {
            $this->redis->del($keys);
        }

        parent::tearDown();
    }

    public function test_duplicate_linked_not_overwritten(): void
    {
        $this->submit('a@x.com');
        $original = $this->lastLeadId();

        $this->submit('a@x.com', [
            'name' => 'Impostor Lovelace',
            'automation_need' => 'A second, different ask entirely.',
        ]);
        $duplicate = $this->lastLeadId();

        $this->assertNotSame($original, $duplicate, 'the repeat submission is its own row, not a merge');
        $this->assertSame(2, $this->countInteractions(), 'LFR-DUP-001: both submissions are recorded');

        $link = $this->duplicateLink();
        $this->assertNotNull($link, 'LFR-DUP-001: the repeat is linked to the original');
        $this->assertSame($original, $link['lead_id']);
        $this->assertSame($duplicate, $link['duplicate_lead_id']);

        // LBR-5.5: the original is evidence. It is never rewritten by a later
        // submission claiming to be the same person.
        $this->assertSame('Ada Lovelace', $this->leadName($original), 'the original lead is untouched');
        $this->assertSame('New', $this->leadStatus($original));
    }

    public function test_reanalysis_appends_new_version(): void
    {
        $this->submit('a@x.com');
        $leadId = $this->lastLeadId();

        $this->service->analyze($this->goodAI(), self::TENANT_ID, $leadId);
        $this->service->analyze($this->aiSaying(['summary' => 'Second pass, revised.']), self::TENANT_ID, $leadId);

        $this->assertSame([1, 2], $this->analysisVersions($leadId), 'a re-analysis appends a new version');
        $this->assertSame(
            'Weekly invoice automation enquiry.',
            $this->analysisSummaries($leadId)[0],
            'the earlier verdict is never updated in place',
        );
    }

    public function test_deterministic_rule_overrides_ai(): void
    {
        $decision = $this->service->route(
            $this->aiSaying(['priority' => 'low', 'owner' => 'archive']),
            'owner=always-sales'
        );

        $this->assertSame('sales', $decision->owner, 'LFR-ROUTE-001: the business rule wins, the AI only suggests');
    }

    public function test_ai_input_excludes_unnecessary_fields(): void
    {
        $payload = $this->service->buildAIRequest($this->leadWith(['ssn' => '123-45-6789']))->payload();

        $this->assertStringNotContainsString('123-45-6789', $payload, 'LFR-AI-002: no PII reaches the model');
        $this->assertStringNotContainsString('ssn', $payload);
        $this->assertStringNotContainsString('ada@example.com', $payload, 'the address itself is not needed');
        $this->assertStringContainsString('invoice', $payload, 'the field the model actually needs survives');
    }

    public function test_low_confidence_routes_to_review(): void
    {
        $result = $this->service->analyze($this->aiSaying(['confidence' => 0.2]), self::TENANT_ID);

        $this->assertSame('Review', $result->status, 'LFR-AI-003: an unsure model hands over to a human');
    }

    public function test_analysis_schema_fields_present(): void
    {
        $analysis = $this->service->analyze($this->goodAI(), self::TENANT_ID)->toArray();

        foreach (self::SCHEMA_FIELDS as $field) {
            $this->assertArrayHasKey($field, $analysis, sprintf('LFR-AI-001: "%s" is part of the schema', $field));
        }
    }

    /**
     * @param  array<string, string> $overrides
     * @return array{status: int, correlation_id: string, message: string, errors: array<string, string>}
     */
    private function submit(string $email, array $overrides = []): array
    {
        return $this->service->capture(array_merge([
            'name' => 'Ada Lovelace',
            'email' => $email,
            'company' => 'Analytical Engines',
            'phone' => '+1 (555) 010-1234',
            'automation_need' => 'Automate the weekly invoice run.',
            'website' => '',
            'ip_hash' => 'analysis-routing-test-hash',
        ], $overrides), self::TENANT_ID);
    }

    /**
     * A complete, confident model verdict.
     *
     * @return array<string, mixed>
     */
    private function goodAI(): array
    {
        return [
            'summary' => 'Weekly invoice automation enquiry.',
            'intent' => 'buy',
            'category' => 'finance_automation',
            'urgency' => 'medium',
            'next_step' => 'Book a scoping call.',
            'risk_flags' => ['none'],
            'confidence' => 0.91,
            'rationale' => 'Named a concrete recurring workflow and a budget owner.',
        ];
    }

    /**
     * @param  array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function aiSaying(array $overrides): array
    {
        return array_merge($this->goodAI(), $overrides);
    }

    /**
     * @param  array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function leadWith(array $overrides): array
    {
        return array_merge([
            'name' => 'Ada Lovelace',
            'email' => 'ada@example.com',
            'company' => 'Analytical Engines',
            'phone' => '+1 (555) 010-1234',
            'automation_need' => 'Automate the weekly invoice run.',
            'ip_hash' => 'analysis-routing-test-hash',
        ], $overrides);
    }

    private function countInteractions(): int
    {
        return $this->scalarInt('SELECT COUNT(*) FROM lead_interactions WHERE tenant_id = ' . self::TENANT_ID);
    }

    /**
     * @return array{lead_id: int, duplicate_lead_id: int}|null
     */
    private function duplicateLink(): ?array
    {
        $rows = $this->rows(
            'SELECT lead_id, duplicate_lead_id FROM lead_duplicates WHERE tenant_id = ' . self::TENANT_ID
            . ' ORDER BY id DESC LIMIT 1'
        );

        if ($rows === []) {
            return null;
        }

        return [
            'lead_id' => (int) $rows[0]['lead_id'],
            'duplicate_lead_id' => (int) $rows[0]['duplicate_lead_id'],
        ];
    }

    /**
     * @return list<int>
     */
    private function analysisVersions(int $leadId): array
    {
        $versions = [];

        foreach ($this->decodedAnalyses($leadId) as $analysis) {
            $version = $analysis['version'] ?? null;
            $versions[] = is_numeric($version) ? (int) $version : 0;
        }

        return $versions;
    }

    /**
     * @return list<string>
     */
    private function analysisSummaries(int $leadId): array
    {
        $summaries = [];

        foreach ($this->decodedAnalyses($leadId) as $analysis) {
            $summary = $analysis['summary'] ?? null;
            $summaries[] = is_string($summary) ? $summary : '';
        }

        return $summaries;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function decodedAnalyses(int $leadId): array
    {
        $decoded = [];

        $rows = $this->rows(
            'SELECT analysis_json FROM lead_ai_analyses WHERE tenant_id = ' . self::TENANT_ID
            . ' AND lead_id = ' . $leadId . ' AND analysis_json IS NOT NULL ORDER BY id ASC'
        );

        foreach ($rows as $row) {
            $json = $row['analysis_json'];
            $value = is_string($json) ? json_decode($json, true) : null;
            if (is_array($value)) {
                /** @var array<string, mixed> $value */
                $decoded[] = $value;
            }
        }

        return $decoded;
    }

    private function lastLeadId(): int
    {
        return $this->scalarInt(
            'SELECT id FROM leads WHERE tenant_id = ' . self::TENANT_ID . ' ORDER BY id DESC LIMIT 1'
        );
    }

    private function leadName(int $leadId): string
    {
        return $this->scalarString(
            'SELECT name FROM leads WHERE tenant_id = ' . self::TENANT_ID . ' AND id = ' . $leadId
        );
    }

    private function leadStatus(int $leadId): string
    {
        return $this->scalarString(
            'SELECT status FROM leads WHERE tenant_id = ' . self::TENANT_ID . ' AND id = ' . $leadId
        );
    }

    private function scalarInt(string $sql): int
    {
        $rows = $this->rows($sql);
        if ($rows === []) {
            return 0;
        }

        $value = array_values($rows[0])[0] ?? null;

        return is_numeric($value) ? (int) $value : 0;
    }

    private function scalarString(string $sql): string
    {
        $rows = $this->rows($sql);
        if ($rows === []) {
            return '';
        }

        $value = array_values($rows[0])[0] ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function rows(string $sql): array
    {
        $statement = $this->pdo->query($sql);
        self::assertNotFalse($statement, 'the probe query must execute');

        /** @var list<array<string, mixed>> $rows */
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);

        return $rows;
    }
}
