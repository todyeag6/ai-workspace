<?php

declare(strict_types=1);

namespace App\Console;

use App\Agents\AgentRegistry;

/**
 * The HTTP edge of the agent console's read surface (FR-AGENT-001, AC-001).
 *
 * THIN ON PURPOSE, in the same shape as App\Dashboard\DashboardController and
 * App\Leads\LeadController: an array request in, an array response out, so it
 * is testable without an HTTP server. All tenant-scoped I/O lives behind
 * AgentRegistry; this class only routes and renders.
 *
 * WHERE THE SCOPING ACTUALLY COMES FROM. This controller takes an
 * AgentRegistry that is already bound to one tenant, and that registry builds
 * its own repositories - both extending App\Data\TenantRepository, which cannot
 * emit a statement without the tenant predicate and binds the tenant value
 * internally. So there is no tenant parameter on this class to get wrong, and
 * no query here that could be written unscoped. The constructor takes the
 * registry rather than a PDO specifically to keep it that way: handed a raw
 * PDO, a future edit could issue an unscoped SELECT, and the whole point of the
 * AC-001 design is that such an edit is not expressible.
 *
 * AUTHORIZATION IS NOT DECIDED HERE. Whether the caller may see this console at
 * all is TenantAuthMiddleware's decision (SEC-005), made in public/index.php
 * before this class is constructed. This class assumes an authorised caller and
 * answers only the narrower question of what to show them.
 *
 * NO MARKUP. Presentation lives in AgentConsoleView, which is a pure string
 * builder - that split is what makes the WCAG and escaping guarantees testable
 * without a database.
 *
 * © AI WebScapes 2026
 */
final class AgentConsoleController
{
    public const PATH = '/console';

    /** The permission code this endpoint requires. See migration 024. */
    public const REQUIRED_PERMISSION = 'agent.console.view';

    private const STATUS_OK = 200;

    private const STATUS_NOT_FOUND = 404;

    private const STATUS_METHOD_NOT_ALLOWED = 405;

    /**
     * @param string $role Presentation-only. It labels the page; it never
     *                     scopes data (the registry does that) and it never
     *                     grants anything (the middleware already did).
     */
    public function __construct(
        private readonly AgentRegistry $registry,
        private readonly AgentConsoleView $view,
        private readonly string $role = 'staff',
        private readonly string $csrfToken = ''
    ) {
    }

    /**
     * @param  array<string, mixed> $request method, path.
     * @return array{status: int, body: array<string, mixed>}
     */
    public function handle(array $request): array
    {
        if ($this->stringField($request, 'path') !== self::PATH) {
            return ['status' => self::STATUS_NOT_FOUND, 'body' => ['message' => 'Not found.']];
        }

        $method = strtoupper($this->stringField($request, 'method'));
        if ($method !== 'GET') {
            return ['status' => self::STATUS_METHOD_NOT_ALLOWED, 'body' => ['message' => 'Method not allowed.']];
        }

        return [
            'status' => self::STATUS_OK,
            'body' => [
                'html' => $this->view->renderAgentList(
                    $this->agents(),
                    $this->role,
                    $this->csrfToken
                ),
            ],
        ];
    }

    /**
     * The tenant's active agents, as the registry reports them.
     *
     * listActive() is already tenant-scoped and already filters to
     * status='active', so this method deliberately adds no filter of its own -
     * a second, weaker filter here would be the thing that drifts.
     *
     * @return list<array{id: int, name: string, owner: string, purpose: string, risk_class: string, status?: string, allowed_tools: list<string>, model_config: array<string, scalar|null>}>
     */
    private function agents(): array
    {
        return $this->registry->listActive();
    }

    /**
     * @param array<string, mixed> $source
     */
    private function stringField(array $source, string $key): string
    {
        $value = $source[$key] ?? '';

        return is_scalar($value) ? (string) $value : '';
    }
}
