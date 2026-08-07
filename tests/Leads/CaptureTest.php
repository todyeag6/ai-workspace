<?php

declare(strict_types=1);

namespace App\Tests\Leads;

use App\Leads\LeadController;
use App\Leads\LeadService;
use App\Security\RateLimiter;
use App\Tests\TestCase;
use Closure;
use Predis\Client;
use RuntimeException;

/**
 * Public lead capture: LFR-CAP-001..004 and LBR-5.1.
 *
 * The endpoint is PUBLIC and UNAUTHENTICATED, so these tests are the evidence
 * for the four defences that stand in place of a session:
 *
 *   LFR-CAP-001  a filled honeypot is ACCEPTED and NOT persisted - a bot must
 *                not learn it was detected, and must not create a row.
 *   LFR-CAP-002  invalid input yields 422 and ZERO records.
 *   LFR-CAP-003  the throttle is fail-CLOSED and lives in Redis, so dropping
 *                cookies does not reset the allowance.
 *   LFR-CAP-004  a valid capture persists exactly once and then queues AI.
 *   LBR-5.1      the AI call happens AFTER the commit, so an AI failure leaves
 *                the lead on disk with status 'Review' rather than losing it.
 *
 * Redis is real (the same store RateLimiterTest uses) because a mocked counter
 * would only prove an INCR was emitted, not that the allowance survives a lost
 * session. Every test allocates its own random bucket so runs cannot collide.
 *
 * © AI WebScapes 2026
 */
final class CaptureTest extends TestCase
{
    private const PATH = '/api/v1/public/leads';

    private const TENANT_ID = '1';

    /**
     * The per-test throttle allowance. The abuse test posts one request MORE
     * than this, so the limit and the loop cannot drift apart.
     */
    private const MAX_REQUESTS = 100;

    private LeadController $app;

    private Client $redis;

    private string $bucket;

    private ?Closure $analyzer = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->redis = new Client(['host' => 'redis', 'port' => 6379]);
        $this->bucket = 'pub:leads:' . bin2hex(random_bytes(6));

        $this->app = $this->buildApp();
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

    public function test_valid_capture_persists_once_then_queues_ai(): void
    {
        $response = $this->app->handle($this->post(self::PATH, $this->validPayload()));

        $this->assertStatus(202, $response);
        $this->assertSame(1, $this->countLeads(), 'a valid capture persists exactly one lead');
        $this->assertNotNull($this->lastCorrelationId(), 'the receipt must carry a correlation id');
        $this->assertSame(1, $this->countAnalyses(), 'the AI analysis is queued after the commit');
    }

    public function test_ai_failure_preserves_lead(): void
    {
        $this->aiWillFail();

        $response = $this->app->handle($this->post(self::PATH, $this->validPayload()));

        $this->assertStatus(202, $response);
        $this->assertSame(1, $this->countLeads(), 'LBR-5.1: the lead survives an AI failure');
        $this->assertSame('Review', $this->leadStatus(), 'a failed analysis parks the lead for review');
    }

    public function test_invalid_input_creates_no_record(): void
    {
        $response = $this->app->handle($this->post(self::PATH, $this->brokenPayload()));

        $this->assertStatus(422, $response);
        $this->assertSame(0, $this->countLeads(), 'LFR-CAP-002: invalid input writes nothing');
    }

    public function test_honeypot_silently_accepts_without_persisting(): void
    {
        $response = $this->app->handle($this->post(self::PATH, $this->payloadWith(['website' => 'bot'])));

        $this->assertStatus(202, $response, 'a bot must not be told it was detected');
        $this->assertSame(0, $this->countLeads(), 'LFR-CAP-001: a honeypot hit is never persisted');
    }

    public function test_abuse_throttled_without_cookies(): void
    {
        $response = ['status' => 0, 'body' => []];

        for ($i = 0; $i <= self::MAX_REQUESTS; $i++) {
            $response = $this->postNoCookies();
        }

        $this->assertStatus(429, $response, 'LFR-CAP-003: the throttle is fail-closed');
    }

    /**
     * @return array<string, string>
     */
    private function validPayload(): array
    {
        return [
            'name' => 'Ada Lovelace',
            'email' => 'ada@example.com',
            'company' => 'Analytical Engines',
            'automation_need' => 'Automate the weekly invoice run.',
            'website' => '',
        ];
    }

    /**
     * Empty name, malformed email, empty need - three independent failures, so
     * the test cannot pass by accident if one validation rule is relaxed.
     *
     * @return array<string, string>
     */
    private function brokenPayload(): array
    {
        return [
            'name' => '',
            'email' => 'not-an-email',
            'company' => '',
            'automation_need' => '',
            'website' => '',
        ];
    }

    /**
     * @param  array<string, string> $overrides
     * @return array<string, string>
     */
    private function payloadWith(array $overrides): array
    {
        return array_merge($this->validPayload(), $overrides);
    }

    /**
     * One request carrying no cookies and no session of any kind - the shape an
     * abusive client uses when it discards state between attempts.
     *
     * @return array{status: int, body: array<string, mixed>}
     */
    private function postNoCookies(): array
    {
        return $this->app->handle($this->post(self::PATH, $this->validPayload(), []));
    }

    /**
     * @param  array<string, string> $payload
     * @param  array<string, string> $server
     * @return array{method: string, path: string, body: array<string, string>, server: array<string, string>}
     */
    private function post(string $path, array $payload, array $server = ['REMOTE_ADDR' => '203.0.113.7']): array
    {
        return [
            'method' => 'POST',
            'path' => $path,
            'body' => $payload,
            'server' => $server,
        ];
    }

    /**
     * Replaces the injected analyzer with one that throws, standing in for the
     * model being down. No real model is ever called from this suite.
     */
    private function aiWillFail(): void
    {
        $this->analyzer = static function (int $leadId, array $lead): array {
            throw new RuntimeException('analyzer unavailable');
        };

        $this->app = $this->buildApp();
    }

    private function buildApp(): LeadController
    {
        $service = new LeadService(
            $this->pdo,
            new RateLimiter($this->redis, $this->bucket, self::MAX_REQUESTS, 60),
            $this->analyzer
        );

        return new LeadController($service, self::TENANT_ID, 'test-ip-hash-secret');
    }

    private function countLeads(): int
    {
        return $this->scalarInt('SELECT COUNT(*) FROM leads WHERE tenant_id = ' . self::TENANT_ID);
    }

    private function countAnalyses(): int
    {
        return $this->scalarInt('SELECT COUNT(*) FROM lead_ai_analyses WHERE tenant_id = ' . self::TENANT_ID);
    }

    private function lastCorrelationId(): ?string
    {
        return $this->scalarString(
            'SELECT correlation_id FROM leads WHERE tenant_id = ' . self::TENANT_ID . ' ORDER BY id DESC LIMIT 1'
        );
    }

    private function leadStatus(): ?string
    {
        return $this->scalarString(
            'SELECT status FROM leads WHERE tenant_id = ' . self::TENANT_ID . ' ORDER BY id DESC LIMIT 1'
        );
    }

    private function scalarInt(string $sql): int
    {
        $statement = $this->pdo->query($sql);
        self::assertNotFalse($statement, 'the probe query must execute');

        return (int) $statement->fetchColumn();
    }

    private function scalarString(string $sql): ?string
    {
        $statement = $this->pdo->query($sql);
        self::assertNotFalse($statement, 'the probe query must execute');

        $value = $statement->fetchColumn();

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @param array{status: int, body: array<string, mixed>} $response
     */
    private function assertStatus(int $expected, array $response, string $message = ''): void
    {
        $this->assertSame($expected, $response['status'], $message);
    }
}
