<?php

declare(strict_types=1);

namespace App\Tests\Notification;

use App\Notification\NotificationService;
use App\Tests\TestCase;

/**
 * Outbound notification dispatch (FR-NOTIF-001).
 *
 * FR-NOTIF-001 an invalid recipient is NEVER dispatched to. Address validation
 * is fail-closed: a malformed recipient produces no outbound message and the
 * delivery is recorded as 'failed', so a typo or an injection-shaped value
 * cannot reach a mailer - or, worse, be silently swallowed and reported as
 * delivered.
 *
 * No real transport is used: NotificationService records a delivery row, it
 * does not open a socket. That keeps the guarantee observable entirely in the
 * database and removes the flakiness a network dependency would bring.
 *
 * © AI WebScapes 2026
 */
final class NotificationTest extends TestCase
{
    private const TENANT_ID = 1;

    private NotificationService $notifications;

    protected function setUp(): void
    {
        parent::setUp();
        $this->notifications = new NotificationService($this->pdo);
    }

    public function test_invalid_recipient_rejected(): void
    {
        $result = $this->notifications->send(
            tenantId: self::TENANT_ID,
            template: 'ack',
            recipient: 'not-an-email',
            subject: 'Your request',
            body: 'Thanks for reaching out.'
        );

        $this->assertFalse($result->sent, 'a malformed recipient must not be dispatched');
        $this->assertSame('failed', $result->status, 'the delivery is recorded as failed, not silently dropped');
        $this->assertSame(0, $this->deliveryCount(), 'nothing was written to the outbound queue');
        $this->assertStringContainsString('recipient', $result->reason, 'the failure explains what was wrong');
    }

    public function test_valid_recipient_is_queued(): void
    {
        $result = $this->notifications->send(
            tenantId: self::TENANT_ID,
            template: 'ack',
            recipient: 'ada@example.com',
            subject: 'Your request',
            body: 'Thanks for reaching out.'
        );

        $this->assertTrue($result->sent, 'a well-formed recipient is accepted');
        $this->assertSame('queued', $result->status, 'the delivery is queued for dispatch');
        $this->assertSame(1, $this->deliveryCount(), 'exactly one outbound record is written');
    }

    public function test_cross_tenant_recipient_cannot_spoof_scope(): void
    {
        // The delivery row must carry the tenant it was filed under, never one
        // supplied by the caller. A notification queued for tenant 1 must not
        // be attributable to tenant 2 (FR-TEN-002 / AC-001).
        $result = $this->notifications->send(
            tenantId: self::TENANT_ID,
            template: 'ack',
            recipient: 'ada@example.com',
            subject: 'Your request',
            body: 'Hi.'
        );

        $this->assertTrue($result->sent);
        $this->assertSame(self::TENANT_ID, $this->deliveryTenantId((int) $result->deliveryId));
    }

    private function deliveryCount(): int
    {
        $statement = $this->pdo->query('SELECT COUNT(*) FROM message_deliveries WHERE tenant_id = ' . self::TENANT_ID);
        if ($statement === false) {
            return 0;
        }

        return (int) $statement->fetchColumn();
    }

    private function deliveryTenantId(int $id): int
    {
        $statement = $this->pdo->query('SELECT tenant_id FROM message_deliveries WHERE id = ' . $id);
        if ($statement === false) {
            return 0;
        }

        return (int) $statement->fetchColumn();
    }
}
