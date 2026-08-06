<?php

declare(strict_types=1);

namespace App\Security;

use App\Audit\AuditLog;
use App\Identity\SessionStore;

/**
 * The authorisation gate every request passes through (SEC-005, AC-001).
 *
 * ORDER OF CHECKS, AND WHY IT IS THIS ORDER
 * -----------------------------------------
 *   1. SESSION      - no server-side session, no identity. A request that
 *                     presents nothing is denied before anything is looked up.
 *   2. CSRF         - state-changing verbs must carry the session's token.
 *                     Checked before authorisation so a forged cross-site POST
 *                     from a legitimately privileged user's browser is stopped
 *                     even though that user WOULD be permitted.
 *   3. PERMISSION   - the AccessPolicy is asked, and it is deny-by-default.
 *   4. OBJECT       - the named object is resolved through the tenant-scoped
 *                     locator and its tenant is re-checked against the subject.
 *
 * Every failing branch answers 403 and writes an authz.deny audit record
 * (FR-AUD-001). There is no 404 branch: see the note on
 * AuthorizationResult, and REASON_OBJECT_UNAVAILABLE below.
 *
 * DEPENDS ON THE INTERFACE, NOT THE POLICY. The constructor type-hints
 * AccessPolicy (ADR-0002). Naming RbacPolicy here would make the middleware -
 * the one component every request touches - the thing that has to change when
 * the authorisation model does.
 *
 * © AI WebScapes 2026
 */
final class TenantAuthMiddleware
{
    public const REASON_NO_SESSION = 'authz.no_session';
    public const REASON_CSRF = 'authz.csrf';
    public const REASON_FORBIDDEN = 'authz.forbidden';

    /**
     * ONE reason for two situations, deliberately: "this object does not
     * exist" and "this object belongs to another tenant" must be a single
     * indistinguishable answer, or the difference between them enumerates
     * other tenants' ids (AC-001). The audit record keeps the reason the
     * caller never sees.
     */
    public const REASON_OBJECT_UNAVAILABLE = 'authz.object_unavailable';

    public const EVENT_DENY = 'authz.deny';

    private CsrfGuard $csrf;

    public function __construct(
        private SessionStore $sessions,
        private AccessPolicy $policy,
        private AuditLog $audit,
        private ?ResourceLocator $locator = null,
        ?CsrfGuard $csrf = null
    ) {
        $this->csrf = $csrf ?? new CsrfGuard();
    }

    /**
     * @param string|null $objectId The object the action names, if any. A
     *                              string because ids arrive from the
     *                              transport as strings and the repository
     *                              binds them safely either way.
     */
    public function authorise(
        ?string $sessionId,
        string $action,
        ?string $objectId = null,
        string $httpMethod = 'GET',
        ?string $csrfToken = null
    ): AuthorizationResult {
        if ($sessionId === null || $sessionId === '') {
            // No tenant is known for an anonymous caller, and audit_log rows
            // are tenant-scoped by construction, so there is nothing truthful
            // to write here. The denial is still returned - it is simply not
            // attributable, and inventing a tenant for it would corrupt every
            // per-tenant audit query.
            return AuthorizationResult::deny(self::REASON_NO_SESSION);
        }

        $subject = $this->sessions->read($sessionId);
        if ($subject === null) {
            return AuthorizationResult::deny(self::REASON_NO_SESSION);
        }

        if ($this->csrf->requiresToken($httpMethod) && !$this->csrf->verify($subject->csrfToken(), $csrfToken)) {
            return $this->refuse($subject, $action, $objectId, self::REASON_CSRF);
        }

        if (!$this->policy->permits($subject, $action)) {
            return $this->refuse($subject, $action, $objectId, self::REASON_FORBIDDEN);
        }

        if ($objectId === null || $objectId === '') {
            return AuthorizationResult::allow($subject);
        }

        $object = $this->locator?->locate($subject, $objectId);
        if ($object === null) {
            // Missing, or another tenant's - one answer for both.
            return $this->refuse($subject, $action, $objectId, self::REASON_OBJECT_UNAVAILABLE);
        }

        if ($object->tenantId() !== $subject->tenantId()) {
            // Unreachable through a locator that scopes properly, which is
            // exactly why it is checked: AC-001 must not rest on the locator
            // implementation staying careful.
            return $this->refuse($subject, $action, $objectId, self::REASON_OBJECT_UNAVAILABLE);
        }

        if (!$this->policy->permits($subject, $action, $object)) {
            return $this->refuse($subject, $action, $objectId, self::REASON_FORBIDDEN);
        }

        return AuthorizationResult::allow($subject);
    }

    /**
     * Denies AND audits. Private so no branch can deny without leaving a
     * record - the audit write is not a decoration on the decision, it is part
     * of it (FR-AUD-001).
     */
    private function refuse(
        Subject $subject,
        string $action,
        ?string $objectId,
        string $reason
    ): AuthorizationResult {
        $this->audit->denied(
            $subject->tenantId(),
            $subject->userId(),
            self::EVENT_DENY,
            $action,
            $objectId,
            $reason
        );

        return AuthorizationResult::deny($reason, $subject);
    }
}
