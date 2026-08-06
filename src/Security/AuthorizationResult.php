<?php

declare(strict_types=1);

namespace App\Security;

/**
 * The outcome of one authorisation decision: an HTTP status, a machine-readable
 * reason and, when the caller was authenticated, the subject that acted.
 *
 * WHY 403 AND NEVER 404. The two named constructors are allowed() and denied()
 * - there is no notFound(). A "not found" answer for an object that exists in
 * another tenant tells the caller that the id is real, which turns any id space
 * into a cross-tenant directory (AC-001). Both "no such object" and "not your
 * object" therefore come back as denied() with the same reason, and
 * TenantAuthMiddleware has no branch that can produce anything else.
 *
 * The reason string is for the audit trail and for tests, not for the HTTP
 * body: an adapter rendering this to a response should emit a bare 403.
 *
 * © AI WebScapes 2026
 */
final class AuthorizationResult
{
    public const ALLOWED = 200;
    public const DENIED = 403;

    private function __construct(
        private readonly int $status,
        private readonly string $reason,
        private readonly ?Subject $subject
    ) {
    }

    public static function allow(Subject $subject): self
    {
        return new self(self::ALLOWED, 'allowed', $subject);
    }

    public static function deny(string $reason, ?Subject $subject = null): self
    {
        return new self(self::DENIED, $reason, $subject);
    }

    public function status(): int
    {
        return $this->status;
    }

    public function allowed(): bool
    {
        return $this->status === self::ALLOWED;
    }

    public function reason(): string
    {
        return $this->reason;
    }

    public function subject(): ?Subject
    {
        return $this->subject;
    }
}
