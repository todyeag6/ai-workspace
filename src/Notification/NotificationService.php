<?php

declare(strict_types=1);

namespace App\Notification;

use App\Tenancy\TenantScope;
use PDO;

/**
 * Outbound notification dispatch (FR-NOTIF-001).
 *
 * FAIL-CLOSED RECIPIENT VALIDATION. A notification is only ever queued after
 * its recipient passes validation. A malformed address (or an
 * injection-shaped value) produces no outbound row and is recorded as
 * 'failed' with a reason - it is never silently dropped and never reported as
 * delivered. The default is refusal: if the address is not provably valid, it
 * does not leave the system.
 *
 * TENANT SCOPING. The delivery row is filed under the tenant resolved up
 * front by TenantScope; the tenant is bound as a parameter, never interpolated,
 * so a caller cannot attribute a message to a tenant it does not own
 * (FR-TEN-002 / AC-001). This class writes through prepare()+execute() - the
 * sanctioned path the PHPStan NoUnscopedClientQueryRule leaves open.
 *
 * No transport. A "send" records a delivery row; it does not open a socket.
 * Dispatch is a separate operational concern, intentionally out of the request
 * path so the validation guarantee stays observable in the database alone.
 *
 * © AI WebScapes 2026
 */
final class NotificationService
{
    /**
     * A pragmatic, fail-closed envelope check: one @, a non-empty local part,
     * a dotted domain, and no whitespace or angle brackets that would let a
     * header-injection-shaped value through. RFC 5321/5322 are far richer;
     * the security property we need is "this is not an attack surface", which
     * a strict allowlist of characters achieves more reliably than a
     * permissive parser.
     */
    private const RECIPIENT_PATTERN = '/^[^@\s<>,:"\']+@[^@\s<>,:"\']+\.[^@\s<>,:"\']+$/';

    public function __construct(private PDO $pdo)
    {
    }

    public function send(
        int $tenantId,
        string $template,
        string $recipient,
        string $subject,
        string $body,
        string $channel = 'email',
        ?int $leadId = null
    ): NotificationResult {
        $scope = new TenantScope($tenantId);

        if (preg_match(self::RECIPIENT_PATTERN, $recipient) !== 1) {
            return new NotificationResult(
                sent: false,
                status: 'failed',
                reason: 'invalid recipient: ' . $recipient
            );
        }

        $statement = $this->pdo->prepare(
            'INSERT INTO message_deliveries ('
            . TenantScope::COLUMN . ', lead_id, kind, channel, recipient, template_code, body'
            . ') VALUES (:' . TenantScope::PARAM . ', :lead_id, :kind, :channel, :recipient, :template, :body)'
        );
        $scope->bindTo($statement);
        $statement->bindValue('lead_id', $leadId, $leadId === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $statement->bindValue('kind', 'notification');
        $statement->bindValue('channel', $channel);
        $statement->bindValue('recipient', $recipient);
        $statement->bindValue('template', $template);
        $statement->bindValue('body', $subject . "\n\n" . $body);
        $statement->execute();

        $id = $this->pdo->lastInsertId();
        $deliveryId = is_string($id) ? (int) $id : 0;

        return new NotificationResult(
            sent: true,
            status: 'queued',
            deliveryId: $deliveryId
        );
    }
}
