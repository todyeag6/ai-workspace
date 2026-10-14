<?php

declare(strict_types=1);

namespace App\Console;

/**
 * Renders the agent console pages as WCAG 2.2 AA HTML (A11Y-001..006).
 *
 * PURE PRESENTATION, NO I/O. Every method takes a value (or a list of agent
 * rows) and returns a string. Nothing here reads a database, resolves a tenant
 * or authorises anything - that is the controllers' job. The split is what
 * makes the accessibility and escaping guarantees unit-testable without MySQL
 * (tests/Console/AgentConsoleViewTest), and it mirrors the shape
 * App\Dashboard\DashboardController::renderHtml() established for P1-T15.
 *
 * WHAT THE MARKUP GUARANTEES
 *  - A11Y-001 perceivable: lang, <title>, one <h1>, labelled landmarks,
 *    captioned table with scoped headers.
 *  - A11Y-002 operable: native <a>/<button>/<input> only, skip link, no trap.
 *    Focus styling lives in the external stylesheet.
 *  - A11Y-003 understandable: field errors get aria-invalid + aria-describedby
 *    pointing at a role="alert" message.
 *  - A11Y-004 robust: state is conveyed by TEXT plus a decorative symbol that
 *    is aria-hidden, never by colour alone.
 *  - WCAG 2.2 SC 3.3.8 (new in 2.2): the login form keeps `autocomplete` on
 *    both fields and blocks neither paste nor autofill.
 *
 * NO INLINE STYLE, NO INLINE SCRIPT. The CSP is "default-src 'self';
 * style-src 'self'" with no script-src 'unsafe-inline'. An inline <style>
 * would force the weakest possible style policy - the SEC-009 pen-test finding
 * on the dashboard - and an inline <script> would simply not execute. The
 * stylesheet is a separate same-origin asset, and the one place the dashboard
 * needed JS (reading the double-submit CSRF cookie) does not arise here: the
 * console's CSRF token comes from the server-side session and is rendered
 * directly into the hidden field, so no script is needed at all.
 *
 * EVERY INTERPOLATED VALUE GOES THROUGH Html::escape(). Untrusted content is
 * data (SEC-010 / SFR-AI-002) - agent names, owners and purposes are
 * operator-typed and model output is model-controlled, so none of them may
 * become markup.
 *
 * © AI WebScapes 2026
 */
final class AgentConsoleView
{
    /**
     * The console stylesheet, served as a static same-origin asset. A constant
     * so the markup and the served file cannot drift apart (same pattern as
     * DashboardController::STYLESHEET_PATH).
     */
    public const STYLESHEET_PATH = '/assets/console.css';

    /**
     * Symbol per agent status. Text accompanies every symbol (A11Y-004); these
     * are decoration, marked aria-hidden at the point of use.
     *
     * @var array<string, string>
     */
    private const STATUS_SYMBOLS = [
        'active' => '●',
        'disabled' => '○',
        'retired' => '✕',
    ];

    /**
     * @param list<array{id: int, name: string, owner: string, purpose: string, risk_class: string, status?: string, allowed_tools: list<string>, model_config: array<string, scalar|null>}> $agents
     */
    public function renderAgentList(array $agents, string $role = 'staff', string $csrfToken = ''): string
    {
        $rows = '';
        foreach ($agents as $agent) {
            $rows .= $this->agentRow($agent);
        }

        $body = $agents === []
            ? '<p class="empty-state">No active agents are registered for this tenant.</p>'
            : '<table>'
                . '<caption class="visually-hidden">Registered agents for this tenant, with their status, '
                . 'risk class and permitted tools. Status is shown by symbol and label, not colour alone.</caption>'
                . '<thead><tr>'
                . '<th scope="col">Agent</th>'
                . '<th scope="col">Status</th>'
                . '<th scope="col">Risk</th>'
                . '<th scope="col">Owner</th>'
                . '<th scope="col">Purpose</th>'
                . '</tr></thead>'
                . '<tbody>' . $rows . '</tbody>'
                . '</table>';

        return $this->page(
            'Agent Console',
            '<header role="banner"><h1>Agent Console</h1>'
            . '<p class="role-badge">Signed in as: <strong>' . Html::escape($role) . '</strong></p></header>'
            . '<main id="main" role="main">'
            . '<section aria-labelledby="agents-h">'
            . '<h2 id="agents-h">Registered agents</h2>'
            . $body
            . '</section>'
            . $this->invokeForm($agents, $csrfToken)
            . '</main>'
        );
    }

    /**
     * The invocation form. A plain HTML form POST - no JavaScript - because the
     * CSRF token is the session's server-side token, available at render time.
     *
     * @param list<array{id: int, name: string, owner: string, purpose: string, risk_class: string, status?: string, allowed_tools: list<string>, model_config: array<string, scalar|null>}> $agents
     */
    public function invokeForm(array $agents, string $csrfToken = ''): string
    {
        $active = [];
        foreach ($agents as $agent) {
            if (($agent['status'] ?? '') === 'active') {
                $active[] = $agent;
            }
        }

        if ($active === []) {
            return '<section aria-labelledby="invoke-h">'
                . '<h2 id="invoke-h">Run an agent</h2>'
                . '<p>No active agent is available to run.</p>'
                . '</section>';
        }

        $options = '';
        foreach ($active as $agent) {
            $options .= '<option value="' . Html::escape((string) $agent['id']) . '">'
                . Html::escape((string) $agent['name'])
                . '</option>';
        }

        return '<section aria-labelledby="invoke-h">'
            . '<h2 id="invoke-h">Run an agent</h2>'
            . '<form method="post" action="/console/invoke">'
            . '<input type="hidden" name="csrf_token" value="' . Html::escape($csrfToken) . '">'
            . '<div class="field">'
            . '<label for="invoke-agent">Agent</label>'
            . '<select id="invoke-agent" name="agent_id">' . $options . '</select>'
            . '</div>'
            . '<div class="field">'
            . '<label for="invoke-work">Work to perform</label>'
            . '<textarea id="invoke-work" name="work_description" rows="5" aria-describedby="invoke-work-hint"></textarea>'
            . '<p class="field-hint" id="invoke-work-hint">Describe the task for the agent. '
            . 'The request is recorded against this tenant.</p>'
            . '</div>'
            . '<button type="submit">Run agent</button>'
            . '</form>'
            . '</section>';
    }

    /**
     * The sign-in page.
     *
     * WCAG 2.2 SC 3.3.8 (Accessible Authentication, Minimum, AA) is why this
     * form carries `autocomplete` on both fields and no paste/autofill
     * blocking: a login is a cognitive function test, and the standard requires
     * a mechanism (password-manager support) rather than making the user
     * recall. https://www.w3.org/TR/WCAG22/
     *
     * @param array<string, string> $errors field => message (A11Y-003).
     */
    public function renderLogin(array $errors = [], string $csrfToken = '', string $notice = ''): string
    {
        $emailInvalid = isset($errors['email']);
        $passwordInvalid = isset($errors['password']);

        $errorHtml = static function (string $field, string $message): string {
            return '<p class="field-error" id="' . Html::escape($field) . '-error" role="alert">'
                . Html::escape($message) . '</p>';
        };

        $noticeHtml = $notice === ''
            ? ''
            : '<p class="notice" role="status">' . Html::escape($notice) . '</p>';

        $form = '<form method="post" action="/login">'
            . '<input type="hidden" name="csrf_token" value="' . Html::escape($csrfToken) . '">'
            . '<div class="field">'
            . '<label for="login-email">Email address</label>'
            . '<input type="email" id="login-email" name="email" autocomplete="username"'
            . ' aria-required="true" aria-invalid="' . ($emailInvalid ? 'true' : 'false') . '"'
            . ($emailInvalid ? ' aria-describedby="email-error"' : '') . '>'
            . ($emailInvalid ? $errorHtml('email', $errors['email']) : '')
            . '</div>'
            . '<div class="field">'
            . '<label for="login-password">Password</label>'
            . '<input type="password" id="login-password" name="password" autocomplete="current-password"'
            . ' aria-required="true" aria-invalid="' . ($passwordInvalid ? 'true' : 'false') . '"'
            . ($passwordInvalid ? ' aria-describedby="password-error"' : '') . '>'
            . ($passwordInvalid ? $errorHtml('password', $errors['password']) : '')
            . '</div>'
            . '<button type="submit">Sign in</button>'
            . '</form>';

        return $this->page(
            'Sign in',
            '<header role="banner"><h1>Sign in</h1></header>'
            . '<main id="main" role="main">'
            . '<section aria-labelledby="signin-h">'
            . '<h2 id="signin-h">Operator sign in</h2>'
            . $noticeHtml
            . $form
            . '</section>'
            . '</main>'
        );
    }

    /**
     * One table row.
     *
     * `status` is OPTIONAL because AgentRegistry::listActive() does not return
     * it - it selects only active agents, so status is implied rather than
     * carried. Defaulting to 'disabled' keeps the render honest if a caller
     * ever passes an unenriched row: an unknown status must not be displayed as
     * active.
     *
     * @param array{id: int, name: string, owner: string, purpose: string, risk_class: string, status?: string, allowed_tools: list<string>, model_config: array<string, scalar|null>} $agent
     */
    private function agentRow(array $agent): string
    {
        $status = (string) ($agent['status'] ?? 'disabled');
        $symbol = self::STATUS_SYMBOLS[$status] ?? '•';

        // A11Y-004: the glyph is decorative and the label is the real content,
        // so a screen reader announces the state and a colour-blind or
        // greyscale reader still sees it.
        $statusCell = '<span class="status-icon" aria-hidden="true">' . Html::escape($symbol) . '</span>'
            . '<span class="status-label">' . Html::escape($status) . '</span>';

        return '<tr>'
            . '<td>' . Html::escape((string) $agent['name']) . '</td>'
            . '<td class="status-cell">' . $statusCell . '</td>'
            . '<td>' . Html::escape((string) $agent['risk_class']) . '</td>'
            . '<td>' . Html::escape((string) $agent['owner']) . '</td>'
            . '<td>' . Html::escape((string) $agent['purpose']) . '</td>'
            . '</tr>';
    }

    /**
     * The shared page shell. Every page gets the same lang, charset, viewport,
     * skip link, stylesheet link and landmark set, so an accessibility fix here
     * fixes every page rather than one.
     */
    private function page(string $title, string $body): string
    {
        return '<!doctype html>'
            . '<html lang="en">'
            . '<head>'
            . '<meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<title>' . Html::escape($title) . '</title>'
            . '<link rel="stylesheet" href="' . self::STYLESHEET_PATH . '">'
            . '</head>'
            . '<body>'
            . '<a class="skip-link" href="#main">Skip to main content</a>'
            . $body
            . '<footer role="contentinfo"><p>AI WebScapes operations console.</p></footer>'
            . '</body>'
            . '</html>';
    }
}
