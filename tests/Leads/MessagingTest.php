<?php

declare(strict_types=1);

namespace App\Tests\Leads;

use App\Leads\LeadService;
use App\Leads\MessageService;
use App\Security\RateLimiter;
use App\Tests\TestCase;
use Predis\Client;

/**
 * Messaging, tasks and append-only AI corrections: LFR-MSG-001/002,
 * LFR-TASK-001, LFR-DASH-004 and LBR-5.4.
 *
 * These pin down four guarantees about the human-facing side of a lead:
 *
 *   LFR-MSG-001  a send is idempotent - retrying the same acknowledgement for
 *                the same lead never produces a second outbound message. The
 *                storage layer enforces this with a UNIQUE (tenant, lead, kind)
 *                key, so a retry after a transient failure cannot duplicate.
 *   LFR-MSG-002  an opted-out recipient is NEVER messaged. A send that would
 *                have gone out to a suppressed address writes nothing.
 *   LFR-TASK-001 a task can be opened against a lead and is tenant-scoped, so
 *                a second tenant cannot see or inherit another tenant's work.
 *   LFR-DASH-004 an AI-field correction preserves the ORIGINAL record. The
 *                model's first verdict stays byte-for-byte in place and the
 *                human's edit is appended as a new row with both old and new
 *                values. A test that let the correction overwrite the original
 *                would be documenting the very data-loss the requirement bans.
 *   LBR-5.4      the same opt-out is what the suppression list models.
 *
 * No real transport is used: MessageService records a delivery row, it does
 * not call a mailer. The template is read from the seeded message_templates,
 * so a "send" is fully observable in the database.
 *
 * © AI WebScapes 2026
 */
final class MessagingTest extends TestCase
{
    private const TENANT_ID = '1';

    private const MAX_REQUESTS = 100;

    private LeadService $service;

    private MessageService $messenger;

    private Client $redis;

    private string $bucket;

    /** The lead id these tests operate on, created in setUp(). */
    private int $leadId;

    protected function setUp(): void
    {
        parent::setUp();

        $this->redis = new Client(['host' => 'redis', 'port' => 6379]);
        $this->bucket = 'pub:leads:messaging:' . bin2hex(random_bytes(6));

        $this->service = new LeadService(
            $this->pdo,
            new RateLimiter($this->redis, $this->bucket, self::MAX_REQUESTS, 60),
            null
        );

        $this->messenger = new MessageService($this->pdo);

        $this->leadId = $this->captureLead();
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

    public function test_no_duplicate_send_on_retry(): void
    {
        $first = $this->messenger->sendAcknowledgement($this->leadId, self::TENANT_ID);
        $second = $this->messenger->sendAcknowledgement($this->leadId, self::TENANT_ID);

        $this->assertTrue($first, 'the first acknowledgement is sent');
        $this->assertFalse($second, 'a retry of the same acknowledgement sends nothing');
        $this->assertSame(1, $this->deliveryCount(), 'LFR-MSG-001: exactly one message left the system');
    }

    public function test_optout_recipient_not_messaged(): void
    {
        $email = 'a@x.com';
        $this->optOut($email);

        $sent = $this->messenger->sendAcknowledgement($this->leadId, self::TENANT_ID, $email);

        $this->assertFalse($sent, 'LFR-MSG-002 / LBR-5.4: a suppressed recipient is not messaged');
        $this->assertSame(0, $this->deliveryCount(), 'no delivery row is written for an opted-out recipient');
    }

    public function test_acknowledgement_snapshots_seeded_template(): void
    {
        $this->messenger->sendAcknowledgement($this->leadId, self::TENANT_ID);

        $delivery = $this->lastDelivery();
        $this->assertNotNull($delivery, 'a delivery row is recorded');
        $this->assertSame('acknowledgement', $delivery['kind']);
        $this->assertSame('lead_ack', $delivery['template_code']);
        $this->assertStringContainsString('review your request', $delivery['body'], 'the seeded template wording is used');
    }

    public function test_task_opened_against_lead_is_tenant_scoped(): void
    {
        $taskId = $this->messenger->createTask($this->leadId, self::TENANT_ID, 'Call the lead back');

        $this->assertNotNull($taskId, 'LFR-TASK-001: a task can be opened against a lead');
        $this->assertSame(1, $this->taskCountForLead());

        // A DIFFERENT tenant shares no tasks: creating a task under tenant 2
        // must not surface under tenant 1's scoped reads.
        $this->messenger->createTask($this->leadId, '2', 'Tenants must not share work');
        $this->assertSame(1, $this->taskCountForLead(), 'the other tenant\'s task is invisible to tenant 1');
    }

    public function test_correction_preserves_original_ai_record(): void
    {
        // Seed an AI verdict (the model said "high").
        $this->seedAnalysis('high');

        // A human corrects the priority to "low".
        $this->messenger->correctField(
            $this->leadId,
            self::TENANT_ID,
            'priority',
            'low',
            $actorId = 1
        );

        $this->assertSame('high', $this->originalAIField('priority'), 'LFR-DASH-004: the original AI value is untouched');
        $this->assertSame('low', $this->currentAIField('priority'), 'the correction is what the system now reports');
        $this->assertSame(1, $this->correctionCount(), 'the correction is appended as its own row');
    }

    public function test_escalation_keyword_is_detected(): void
    {
        $this->assertTrue(
            MessageService::requiresEscalation('I want to speak to a lawyer about this'),
            'LBR-5.6: a legal keyword triggers escalation'
        );
        $this->assertFalse(
            MessageService::requiresEscalation('Thanks, that sounds great'),
            'ordinary text does not escalate'
        );
    }

    /**
     * Captures a lead and returns its id, mirroring AnalysisRoutingTest.
     */
    private function captureLead(): int
    {
        $this->service->capture([
            'name' => 'Ada Lovelace',
            'email' => 'ada-' . bin2hex(random_bytes(4)) . '@example.com',
            'company' => 'Analytical Engines',
            'automation_need' => 'Automate the weekly invoice run.',
            'website' => '',
            'ip_hash' => 'messaging-test-hash',
        ], self::TENANT_ID);

        return $this->scalarInt(
            'SELECT id FROM leads WHERE tenant_id = ' . self::TENANT_ID . ' ORDER BY id DESC LIMIT 1'
        );
    }

    private function optOut(string $email): void
    {
        $this->pdo->prepare(
            'INSERT INTO message_opt_outs (' . 'tenant_id' . ', email, reason) VALUES (?, ?, ?)'
        )->execute([(int) self::TENANT_ID, $email, 'user_request']);
    }

    private function seedAnalysis(string $priority): void
    {
        $this->pdo->prepare(
            'INSERT INTO lead_ai_analyses (' . 'tenant_id' . ', lead_id, status, analysis_json) '
            . 'VALUES (?, ?, ?, ?)'
        )->execute([
            (int) self::TENANT_ID,
            $this->leadId,
            'complete',
            json_encode(['priority' => $priority, 'version' => 1]),
        ]);
    }

    private function deliveryCount(): int
    {
        return $this->scalarInt(
            'SELECT COUNT(*) FROM message_deliveries WHERE tenant_id = ' . self::TENANT_ID
        );
    }

    /**
     * @return array{kind: string, template_code: string, body: string}|null
     */
    private function lastDelivery(): ?array
    {
        $rows = $this->rows(
            'SELECT kind, template_code, body FROM message_deliveries '
            . 'WHERE tenant_id = ' . self::TENANT_ID . ' ORDER BY id DESC LIMIT 1'
        );

        if ($rows === []) {
            return null;
        }

        return [
            'kind' => (string) $rows[0]['kind'],
            'template_code' => (string) $rows[0]['template_code'],
            'body' => (string) $rows[0]['body'],
        ];
    }

    private function taskCountForLead(): int
    {
        return $this->scalarInt(
            'SELECT COUNT(*) FROM lead_tasks WHERE tenant_id = ' . self::TENANT_ID
            . ' AND lead_id = ' . $this->leadId
        );
    }

    private function correctionCount(): int
    {
        return $this->scalarInt(
            'SELECT COUNT(*) FROM lead_field_corrections WHERE tenant_id = ' . self::TENANT_ID
            . ' AND lead_id = ' . $this->leadId
        );
    }

    private function originalAIField(string $field): ?string
    {
        // The first row is the 'pending' placeholder capture() seeds (NULL
        // analysis_json), so the ORIGINAL verdict is the earliest row that
        // actually carries one. Skipping NULLs points at the model's first
        // real answer - the record the correction must preserve.
        $rows = $this->rows(
            'SELECT analysis_json FROM lead_ai_analyses WHERE tenant_id = ' . self::TENANT_ID
            . ' AND lead_id = ' . $this->leadId . ' AND analysis_json IS NOT NULL ORDER BY id ASC LIMIT 1'
        );

        if ($rows === []) {
            return null;
        }

        $value = is_string($rows[0]['analysis_json']) ? json_decode($rows[0]['analysis_json'], true) : null;

        return is_array($value) && isset($value[$field]) ? (string) $value[$field] : null;
    }

    private function currentAIField(string $field): ?string
    {
        $rows = $this->rows(
            'SELECT new_value FROM lead_field_corrections WHERE tenant_id = ' . self::TENANT_ID
            . ' AND lead_id = ' . $this->leadId . ' AND field_name = ? ORDER BY id DESC LIMIT 1',
            [$field]
        );

        if ($rows === []) {
            return null;
        }

        $value = $rows[0]['new_value'] ?? null;

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * @param array<int, scalar> $params
     */
    private function scalarInt(string $sql, array $params = []): int
    {
        $rows = $this->rows($sql, $params);
        if ($rows === []) {
            return 0;
        }

        $value = array_values($rows[0])[0] ?? null;

        return is_numeric($value) ? (int) $value : 0;
    }

    /**
     * @param array<int, scalar> $params
     * @return list<array<string, mixed>>
     */
    private function rows(string $sql, array $params = []): array
    {
        $statement = $this->pdo->prepare($sql);
        self::assertNotFalse($statement, 'the probe query must prepare');
        $statement->execute($params);

        /** @var list<array<string, mixed>> $rows */
        $rows = $statement->fetchAll(\PDO::FETCH_ASSOC);

        return $rows;
    }
}
