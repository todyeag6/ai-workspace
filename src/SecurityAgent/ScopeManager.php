<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Audit\AuditLogger;
use App\Tenancy\TenantScope;
use DateTimeImmutable;
use InvalidArgumentException;

/**
 * The gate every scan request passes through (SFR-AUTH-001/002, SBR-3.1, and
 * the P3 exit-gate acceptance tests "expired authorization -> scan cannot
 * start" and "redirect out of scope -> request stops and event is recorded").
 *
 * WHAT THIS CLASS DOES AND DELIBERATELY DOES NOT DO
 * -------------------------------------------------
 * It DECIDES. It issues no request, follows no redirect and touches no socket
 * - the same split App\Tools\ToolGateway makes, and for the same reason: the
 * component that judges must not be the component that can be talked into
 * acting. checkRequest() returns a verdict; the scanner holding the connection
 * is what stops.
 *
 * PER REQUEST, NOT PER SCAN
 * -------------------------
 * SFR-AUTH-002 says targets are checked "before every request". That wording
 * is load-bearing: a scan authorised for app.acme.test that receives a 302 to
 * tracker.evil.test has produced a NEW target, and a scan-level check made
 * five minutes ago cannot see it. So callers must call checkRequest() for
 * every URL they are about to fetch, redirects included - and because a
 * redirect target that is out of scope is refused here, it is never followed.
 *
 * ORDER OF CHECKS, AND WHY IT IS THIS ORDER
 * -----------------------------------------
 *   1. authorization - active, complete and in-window. Cheapest, and it is
 *      the check that makes the rest meaningful: an expired engagement should
 *      be refused for expiry, not for a scope detail.
 *   2. canonicalization - pure, no DNS, no fetch (see TargetCanonicalizer).
 *   3. scope - the canonical target must be a listed, in-scope, non-excluded
 *      asset. Absence is refusal.
 *
 * EVERY DENIAL IS RECORDED
 * ------------------------
 * The acceptance test requires the out-of-scope stop to be EVIDENCED, not just
 * to happen. deny() writes an audit event before returning, so there is no
 * path out of this class that refuses silently. Denials are recorded; allows
 * are not, because an allow is followed by the scanner's own request record
 * and duplicating it would bury the refusals.
 *
 * © AI WebScapes 2026
 */
final class ScopeManager
{
    public const DENY_INACTIVE = 'authorization_inactive_or_expired';

    public const DENY_OUT_OF_SCOPE = 'out_of_scope';

    public const DENY_INVALID_TARGET = 'invalid_target';

    public const ALLOWED = 'allowed';

    private const AUDIT_ACTION = 'secauth.scope.deny';

    private const AUDIT_SOURCE = 'scope_manager';

    private const AUDIT_OBJECT_TYPE = 'scan_target';

    /** audit_events.object_id is VARCHAR(64); a long URL is truncated, not refused. */
    private const OBJECT_ID_MAX = 64;

    private int $tenantId;

    public function __construct(
        private readonly AuthorizationRepository $repository,
        private readonly AuditLogger $audit,
        ?int $tenantId
    ) {
        // Throws for null / 0 / negative: an unscoped scope manager is not a
        // representable state (AC-001).
        $this->tenantId = (new TenantScope($tenantId))->id();

        if ($this->repository->tenantId() !== $this->tenantId) {
            throw new InvalidArgumentException(sprintf(
                'ScopeManager is scoped to tenant %d but was given a repository scoped to tenant %d.',
                $this->tenantId,
                $this->repository->tenantId()
            ));
        }
    }

    /**
     * The per-request decision.
     *
     * @param  DateTimeImmutable $now Injected, never read from the clock here,
     *                                so the verdict is deterministic.
     * @return array{allowed: bool, reason: string, target: string}
     */
    public function checkRequest(int $authorizationId, string $rawTarget, DateTimeImmutable $now): array
    {
        // Never throws - a denial must be recordable even for input too
        // malformed to canonicalize.
        $auditTarget = TargetCanonicalizer::forAudit($rawTarget);

        // (a) SFR-AUTH-001: active authorization, or nothing happens. A row
        // that is missing timing / contacts / techniques fails here too, via
        // Authorization::canSchedule() (SBR-3.1).
        $authorization = $this->repository->findById($authorizationId);
        if ($authorization === null || !$authorization->canSchedule($now)) {
            return $this->deny(self::DENY_INACTIVE, $auditTarget);
        }

        // (b) SFR-AUTH-002: canonicalize BEFORE matching, so spelling cannot
        // smuggle a target past the scope list.
        try {
            $canonical = TargetCanonicalizer::canonicalize($rawTarget);
        } catch (InvalidArgumentException) {
            return $this->deny(self::DENY_INVALID_TARGET, $auditTarget);
        }

        if (!$this->repository->isTargetInScope($authorizationId, $canonical)) {
            return $this->deny(self::DENY_OUT_OF_SCOPE, $canonical);
        }

        return [
            'allowed' => true,
            'reason' => self::ALLOWED,
            'target' => $canonical,
        ];
    }

    /**
     * Convenience for call sites that only branch on the verdict.
     */
    public function isAllowed(int $authorizationId, string $rawTarget, DateTimeImmutable $now): bool
    {
        return $this->checkRequest($authorizationId, $rawTarget, $now)['allowed'];
    }

    /**
     * Records the refusal, then returns it. The write happens first so a
     * caller cannot receive a denial that was never evidenced.
     *
     * The detail is written with spaces rather than underscores on purpose:
     * AuditLogger redacts any run of 16+ word characters as a possible leaked
     * secret, which would turn 'authorization_inactive_or_expired' into
     * '[REDACTED]' and lose the reason.
     *
     * @return array{allowed: bool, reason: string, target: string}
     */
    private function deny(string $reason, string $target): array
    {
        $this->audit->record(
            $this->tenantId,
            null,
            self::AUDIT_ACTION,
            self::AUDIT_OBJECT_TYPE,
            mb_substr($target, 0, self::OBJECT_ID_MAX),
            'denied',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            str_replace('_', ' ', $reason)
        );

        return [
            'allowed' => false,
            'reason' => $reason,
            'target' => $target,
        ];
    }
}
