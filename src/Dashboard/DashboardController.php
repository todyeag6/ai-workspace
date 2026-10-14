<?php

declare(strict_types=1);

namespace App\Dashboard;

use PDO;

/**
 * The HTTP edge of the operations dashboard (P1-T15: FR-DASH-001/002,
 * LFR-DASH-001/002/003, A11Y-001..006).
 *
 * Thin on purpose, in the same shape as App\Leads\LeadController: it takes an
 * array request and returns an array response, so it is testable without an HTTP
 * server. All tenant-scoped I/O lives in DashboardRepository; this class only
 * routes, maps onto a status code, and renders.
 *
 * PRESENTATION IS PURE. renderHtml() and leadFormHtml() take a value object /
 * flags and return a string; they perform no I/O and no scoping, so the WCAG
 * rules are unit-testable without MySQL (see tests/Dashboard/AccessibilityTest).
 *
 * SECURITY (SEC-010 / SFR-AI-002): untrusted content is DATA. Every value that
 * reaches the markup - counts, statuses, queue rows - is escaped with
 * htmlspecialchars() at the single escapeSink() point, so a poisoned cell can
 * never become markup. Native form controls + a POST-only action keep the
 * surface tiny.
 *
 * © AI WebScapes 2026
 */
final class DashboardController
{
    public const PATH = '/dashboard';

    /**
     * The dashboard stylesheet, served as a static same-origin asset. Kept as a
     * constant so the markup and the served file cannot drift apart.
     */
    public const STYLESHEET_PATH = '/assets/dashboard.css';

    private const STATUS_ICONS = [
        'New' => '●',            // filled circle
        'Review' => '!',         // exclamation
        'Qualified' => '✓',      // check
        'Disqualified' => '✕',   // cross
        'Converted' => '★',      // star
    ];

    /**
     * @param string $role One of 'staff' | 'admin'. Used only for presentation
     *                     gating in the view, never for data scoping (that is
     *                     the repository's job, bound to $tenantId per call).
     */
    public function __construct(
        private PDO $pdo,
        private int $tenantId,
        private string $role = 'staff'
    ) {
    }

    /**
     * Builds the read-model for a tenant. The repository is tenant-scoped at
     * construction, so this can only ever return THIS tenant's data (AC-001).
     */
    public function forUser(int $tenantId, string $role = 'staff'): DashboardView
    {
        $repo = new DashboardRepository($this->pdo, $tenantId);

        return new DashboardView(
            $repo->leadStatusCounts(),
            $repo->awaitingHuman(),
            $repo->failedDeliveries()
        );
    }

    /**
     * @param array<string, mixed> $request method, path.
     * @return array{status: int, body: array<string, mixed>}
     */
    public function handle(array $request): array
    {
        $path = $this->stringField($request, 'path');
        if ($path !== self::PATH) {
            return ['status' => 404, 'body' => ['message' => 'Not found.']];
        }

        $method = strtoupper($this->stringField($request, 'method'));
        if ($method !== 'GET' && $method !== 'POST') {
            return ['status' => 405, 'body' => ['message' => 'Method not allowed.']];
        }

        $view = $this->forUser($this->tenantId, $this->role);

        return [
            'status' => 200,
            'body' => [
                'html' => $this->renderHtml($view, $this->role),
            ],
        ];
    }

    /**
     * Renders the full dashboard page as WCAG 2.2 AA HTML (A11Y-001..006).
     *
     * Guarantees the automated + manual checks assert:
     *  - A11Y-001 perceivable: lang, <title>, one <h1>, labelled landmarks.
     *  - A11Y-002 keyboard: native <a>/<button>/<input>; no trap; focus styles.
     *  - A11Y-003 form errors: aria-invalid + aria-describedby -> role=alert.
     *  - A11Y-004 / FR-DASH-002: status conveyed by TEXT + shape, not colour.
     *  - reduced-motion + focus-visible + >=4.5:1 contrast in the stylesheet.
     *
     * @param array<string, mixed> $errors Field => message map for the lead form.
     */
    public function renderHtml(DashboardView $view, string $role, array $errors = []): string
    {
        $counts = $view->leadStatusCounts();
        $states = $view->states();

        $rows = '';
        foreach ($states as $state) {
            $count = (int) ($counts[$state] ?? 0);
            $icon = self::STATUS_ICONS[$state] ?? '•';
            // A11Y-004: text + icon, never colour alone. The icon precedes the
            // label so a screen reader announces the state, and the numeric
            // count is its own cell.
            $rows .= '<tr>'
                . '<td class="status-cell"><span class="status-icon" aria-hidden="true">' . $this->escapeSink($icon) . '</span>'
                . '<span class="status-label">' . $this->escapeSink($state) . '</span></td>'
                . '<td class="count">' . $this->escapeSink((string) $count) . '</td>'
                . '</tr>';
        }

        $awaiting = $this->queueHtml($view->awaitingHuman(), 'Awaiting human review', 'analysis id');
        $failed = $this->queueHtml($view->failedDeliveries(), 'Failed deliveries', 'delivery id');

        $roleBadge = $this->escapeSink($role);
        $form = $this->leadFormHtml($errors);

        return '<!doctype html>'
            . '<html lang="en">'
            . '<head>'
            . '<meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<title>Operations Dashboard</title>'
            . $this->styleLink()
            . '</head>'
            . '<body>'
            . '<a class="skip-link" href="#main">Skip to main content</a>'
            . '<header role="banner"><h1>Operations Dashboard</h1>'
            . '<p class="role-badge">Signed in as: <strong>' . $roleBadge . '</strong></p></header>'
            . '<main id="main" role="main">'
            . '<section aria-labelledby="pipeline-h">'
            . '<h2 id="pipeline-h">Lead pipeline</h2>'
            . '<table>'
            . '<caption class="visually-hidden">Lead counts by pipeline state. State shown by icon and label, not colour alone.</caption>'
            . '<thead><tr><th scope="col">State</th><th scope="col">Count</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody>'
            . '</table>'
            . '</section>'
            . $awaiting
            . $failed
            . $form
            . '</main>'
            . '<footer role="contentinfo"><p>AI WebScapes operations console.</p></footer>'
            . '</body>'
            . '</html>';
    }

    /**
     * The lead disposition form with programmatically-determinable errors
     * (A11Y-003). When $errors is non-empty, each named field is flagged
     * aria-invalid="true" and aria-describedby points at a role="alert" message.
     *
     * @param array<string, string> $errors field => message.
     */
    public function leadFormHtml(array $errors = []): string
    {
        $emailErrorId = 'email-error';
        $emailInvalid = isset($errors['email']);
        $emailDescribedBy = $emailInvalid ? ' ' . $emailErrorId : '';
        $emailError = $emailInvalid
            ? '<p class="field-error" id="' . $emailErrorId . '" role="alert">' . $this->escapeSink($errors['email']) . '</p>'
            : '';

        return '<section aria-labelledby="lead-form-h">'
            . '<h2 id="lead-form-h">Add a lead</h2>'
            . '<form method="post" action="/api/v1/public/leads" novalidate>'
            . '<input type="hidden" name="csrf_token" id="csrf-token" value="">'
            . '<div class="field">'
            . '<label for="lead-email">Email address</label>'
            . '<input type="email" id="lead-email" name="email" autocomplete="email"'
            . ' aria-required="true" aria-invalid="' . ($emailInvalid ? 'true' : 'false') . '"'
            . ' aria-describedby="lead-email-hint' . $emailDescribedBy . '">'
            . '<p class="field-hint" id="lead-email-hint">We will only contact this address about the enquiry.</p>'
            . $emailError
            . '</div>'
            . '<div class="field">'
            . '<label for="lead-need">Automation need</label>'
            . '<textarea id="lead-need" name="automation_need" rows="4"></textarea>'
            . '</div>'
            . '<button type="submit">Submit lead</button>'
            . '</form>'
            . '<script>document.getElementById("csrf-token").value=document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/)?.[1]||"";</script>'
            . '</section>';
    }

    /**
     * @param list<array<string, mixed>> $rows
     */
    private function queueHtml(array $rows, string $heading, string $idLabel): string
    {
        if ($rows === []) {
            return '<section aria-labelledby="' . $this->escapeSink($heading) . '-h">'
                . '<h2 id="' . $this->escapeSink($heading) . '-h">' . $this->escapeSink($heading) . '</h2>'
                . '<p>No items.</p>'
                . '</section>';
        }

        $items = '';
        foreach ($rows as $row) {
            $id = is_scalar($row['id'] ?? null) ? (string) $row['id'] : '';
            $detail = '';
            if (isset($row['error']) && is_scalar($row['error']) && (string) $row['error'] !== '') {
                $detail = ': ' . (string) $row['error'];
            } elseif (isset($row['status']) && is_scalar($row['status'])) {
                $detail = ' (' . (string) $row['status'] . ')';
            }
            $items .= '<li>' . $this->escapeSink($idLabel) . ' ' . $this->escapeSink($id) . $this->escapeSink($detail) . '</li>';
        }

        return '<section aria-labelledby="' . $this->escapeSink($heading) . '-h">'
            . '<h2 id="' . $this->escapeSink($heading) . '-h">' . $this->escapeSink($heading) . '</h2>'
            . '<ul>' . $items . '</ul>'
            . '</section>';
    }

    /**
     * A link to the dashboard stylesheet, served same-origin from public/assets.
     *
     * External rather than inline (SEC-004): an inline <style> block forces the
     * Content-Security-Policy to grant style-src 'unsafe-inline', which is the
     * weakest style policy available and was flagged by the SEC-009 pen-test.
     * A linked stylesheet lets the policy stay at style-src 'self'. The file
     * itself carries the A11Y-002 focus-visible, A11Y-004 contrast and
     * reduced-motion rules.
     */
    private function styleLink(): string
    {
        return '<link rel="stylesheet" href="' . self::STYLESHEET_PATH . '">';
    }

    /**
     * The single escape sink. Every interpolated value passes through here so a
     * poisoned cell cannot become markup (SEC-010). Native double-quote
     * encoding closes the attribute-injection path too.
     */
    private function escapeSink(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
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
