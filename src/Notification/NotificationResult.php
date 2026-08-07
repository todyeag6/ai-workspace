<?php

declare(strict_types=1);

namespace App\Notification;

/**
 * The outcome of a single send attempt (FR-NOTIF-001).
 *
 * @property-read bool   $sent     Whether the message was accepted for dispatch.
 * @property-read string $status   'queued' on success, 'failed' on rejection.
 * @property-read string $reason   Why a send failed (empty when it succeeded).
 * @property-read int    $deliveryId The written delivery row, or 0 when none.
 */
final class NotificationResult
{
    public function __construct(
        public readonly bool $sent,
        public readonly string $status,
        public readonly string $reason = '',
        public readonly int $deliveryId = 0
    ) {
    }
}
