<?php

declare(strict_types=1);

namespace App\Console;

use App\Agents\AgentRegistry;
use App\Audit\AuditLog;
use App\Identity\LoginController;
use App\Manager\ManagerOrchestrator;
use App\Security\TenantAuthMiddleware;

/**
 * The invocation endpoint: run a registered agent on behalf of an operator
 * (FR-AGENT-002, FR-TOOL-002, AC-001/002/003, SEC-005).
 *
 * AUTHORIZATION HAPPENS BEFORE ANYTHING ELSE, THROUGH THE EXISTING MIDDLEWARE.
 * TenantAuthMiddleware is asked with action 'agent.invoke' and the agent id as
 * the object. It performs the checks in a fixed order - session, CSRF,
 * permission, object - and each failure carries its own reason constant. This
 * class does NOT re-implement any of that, and it does NOT collapse the reasons
 * into one message, because they call for different human actions:
 *
 *   authz.no_session          -> sign in
 *   authz.csrf                -> re-fetch the form (the token is per-session)
 *   authz.forbidden           -> ask an admin for agent.invoke
 *   authz.object_unavailable  -> the id is wrong OR someone else's
 *
 * The last pair is deliberately ONE reason. App\Security\ResourceLocator
 * collapses "does not exist" and "belongs to another tenant" into a single
 * null, and this endpoint maps that to a single 403 - never a 404, which would
 * let a caller enumerate agent ids across tenants (AC-001).
 *
 * WHY THE AGENT IS RE-READ AFTER AUTHORIZATION. The middleware resolved the
 * agent through the locator to make its decision, but the object it hands back
 * carries only a tenant id (that is all TenantOwned exposes, on purpose). The
 * orchestrator needs the agent's version, prompt and model config, so the agent
 * is fetched again through the tenant-scoped registry. That second read is not
 * a second authorization - it cannot see another tenant's row in the first
 * place - and it is why the disabled check below is meaningful rather than
 * decorative.
 *
 * NO SIDE EFFECT ON INVALID MODEL OUTPUT. The orchestrator dispatches through
 * AIGateway, which returns disposition 'review' with no payload when the model
 * output fails its schema (AC-003). Nothing here inspects or re-interprets that;
 * the gateway owns it.
 *
 * © AI WebScapes 2026
 */
final class AgentInvocationController
{
    public const PATH = '/console/invoke';

    /** The permission code this endpoint requires. See migration 024. */
    public const REQUIRED_PERMISSION = 'agent.invoke';

    private const STATUS_OK = 200;

    private const STATUS_FORBIDDEN = 403;

    private const STATUS_NOT_FOUND = 404;

    private const STATUS_METHOD_NOT_ALLOWED = 405;

    private const STATUS_UNPROCESSABLE = 422;

    public function __construct(
        private readonly TenantAuthMiddleware $middleware,
        private readonly AgentRegistry $registry,
        private readonly ManagerOrchestrator $orchestrator,
        private readonly AuditLog $audit
    ) {
    }

    /**
     * @param  array<string, mixed> $request method, path, body, cookies.
     * @return array{status: int, body: array<string, mixed>}
     */
    public function handle(array $request): array
    {
        if ($this->stringField($request, 'path') !== self::PATH) {
            return $this->response(self::STATUS_NOT_FOUND, ['message' => 'Not found.']);
        }

        $method = strtoupper($this->stringField($request, 'method'));
        if ($method !== 'POST') {
            return $this->response(self::STATUS_METHOD_NOT_ALLOWED, ['message' => 'Method not allowed.']);
        }

        $body = $this->arrayField($request, 'body');
        $agentId = $this->stringField($body, 'agent_id');
        $work = $this->stringField($body, 'work_description');

        $authorisation = $this->middleware->authorise(
            $this->sessionId($request),
            self::REQUIRED_PERMISSION,
            $agentId === '' ? null : $agentId,
            $method,
            $this->stringField($body, 'csrf_token')
        );

        if (!$authorisation->allowed()) {
            // The reason is surfaced so the console can tell the operator what
            // to DO about it. It reveals nothing an authorised caller could not
            // already infer, and an unauthorised caller learns only that they
            // are not allowed - which they already knew.
            return $this->response(self::STATUS_FORBIDDEN, [
                'message' => 'You are not permitted to run this agent.',
                'reason' => $authorisation->reason(),
            ]);
        }

        $agent = $this->registry->find((int) $agentId);
        if ($agent === null) {
            // Unreachable through an authorising middleware, and checked anyway:
            // the two reads must not be able to disagree silently.
            return $this->response(self::STATUS_FORBIDDEN, [
                'message' => 'You are not permitted to run this agent.',
                'reason' => TenantAuthMiddleware::REASON_OBJECT_UNAVAILABLE,
            ]);
        }

        if (($agent['status'] ?? '') !== AgentRegistry::STATUS_ACTIVE) {
            // FR-AGENT-002. A disabled agent must not run even for someone who
            // may invoke agents in general - the permission is about the verb,
            // the status is about this particular agent.
            return $this->response(self::STATUS_FORBIDDEN, [
                'message' => 'That agent is not active.',
                'reason' => 'agent.not_active',
            ]);
        }

        if (trim($work) === '') {
            return $this->response(self::STATUS_UNPROCESSABLE, [
                'message' => 'Describe the work for the agent to perform.',
            ]);
        }

        $result = $this->orchestrator->manage($work);

        // FR-AUD-001: the success path writes its own record. Denials are
        // already recorded by the middleware, so they are not duplicated here.
        $this->audit->record(
            $authorisation->subject()?->tenantId() ?? $this->registry->tenantId(),
            $authorisation->subject()?->userId(),
            'agent.invoke',
            AuditLog::OUTCOME_SUCCESS,
            'agent',
            $agentId,
            sprintf('status=%s', (string) ($result['status'] ?? 'unknown'))
        );

        return $this->response(self::STATUS_OK, [
            'status' => $result['status'] ?? 'unknown',
            'tasks' => $result['tasks'] ?? [],
        ]);
    }

    /**
     * The session id, from the cookie only. Never a query parameter or header:
     * limiting the exchange mechanism to cookies is required by NIST SP
     * 800-63B-4 §5.1.1 and the OWASP Session Management Cheat Sheet, and
     * accepting an id from the URL would let a link carry someone else's
     * session.
     *
     * @param array<string, mixed> $request
     */
    private function sessionId(array $request): ?string
    {
        $cookies = $this->arrayField($request, 'cookies');
        $value = $cookies[LoginController::COOKIE_NAME] ?? '';

        if (!is_scalar($value) || (string) $value === '') {
            return null;
        }

        return (string) $value;
    }

    /**
     * @param array<string, mixed> $source
     */
    private function stringField(array $source, string $key): string
    {
        $value = $source[$key] ?? '';

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * @param  array<string, mixed> $source
     * @return array<string, mixed>
     */
    private function arrayField(array $source, string $key): array
    {
        $value = $source[$key] ?? [];
        if (!is_array($value)) {
            return [];
        }

        $clean = [];
        foreach ($value as $field => $item) {
            if (is_string($field)) {
                $clean[$field] = $item;
            }
        }

        return $clean;
    }

    /**
     * @param  array<string, mixed> $body
     * @return array{status: int, body: array<string, mixed>}
     */
    private function response(int $status, array $body): array
    {
        return ['status' => $status, 'body' => $body];
    }
}
