<?php

declare(strict_types=1);

namespace App\Security;

/**
 * An authenticated identity: who is acting, in which tenant, under which
 * server-side session.
 *
 * WHY THE TENANT LIVES HERE AND NOT IN A REQUEST PARAMETER: AC-001 requires
 * that a caller cannot choose the tenant it reads. A tenant taken from a query
 * string, a header or a form field is caller-controlled by definition. This
 * value object is built ONLY by App\Identity\SessionStore from a server-side
 * session record, so the tenant on it is the one the login established.
 *
 * Immutable by construction (readonly promoted properties): a subject cannot
 * be re-pointed at another tenant halfway through a request.
 *
 * © AI WebScapes 2026
 */
final class Subject
{
    public function __construct(
        private readonly int $tenantId,
        private readonly int $userId,
        private readonly string $sessionId,
        private readonly string $csrfToken,
        private readonly bool $mfaEnrolled
    ) {
    }

    public function tenantId(): int
    {
        return $this->tenantId;
    }

    public function userId(): int
    {
        return $this->userId;
    }

    public function sessionId(): string
    {
        return $this->sessionId;
    }

    public function csrfToken(): string
    {
        return $this->csrfToken;
    }

    /**
     * FR-IDENT-001: whether this credential carries an MFA secret. Reported
     * rather than enforced - the second-factor challenge is a later task, but
     * the identity is MFA-ready from here on.
     */
    public function mfaEnrolled(): bool
    {
        return $this->mfaEnrolled;
    }
}
