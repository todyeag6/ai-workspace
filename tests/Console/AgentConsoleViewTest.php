<?php

declare(strict_types=1);

namespace App\Tests\Console;

use App\Console\AgentConsoleView;
use PHPUnit\Framework\TestCase as Base;

/**
 * WCAG 2.2 AA + SEC-004 for the console's rendered pages (A11Y-001..006).
 *
 * NO DATABASE, deliberately: the view is a pure string builder that performs no
 * I/O, so its accessibility and escaping guarantees are testable in
 * milliseconds and cannot be masked by a fixture problem. Extending
 * App\Tests\TestCase here would open a MySQL transaction to assert string
 * content.
 *
 * THE TWO ASSERTIONS THAT ARE NOT OBVIOUS:
 *
 *   1. NO INLINE <style> OR <script>. The CSP is
 *      "default-src 'self'; style-src 'self'" (App\Bootstrap\SecurityHeaders).
 *      An inline <style> block forces style-src 'unsafe-inline' - the weakest
 *      style policy available, which the SEC-009 pen-test already flagged once
 *      on the dashboard. An inline <script> is worse: the policy has no
 *      script-src 'unsafe-inline' at all, so it would silently not run.
 *
 *   2. autocomplete + no paste-blocking (WCAG 2.2 SC 3.3.8 Accessible
 *      Authentication (Minimum), AA - new in 2.2). A login form must not
 *      require a cognitive function test without an alternative, which in
 *      practice means password-manager autofill and paste must keep working.
 *      https://www.w3.org/TR/WCAG22/
 *
 * © AI WebScapes 2026
 */
final class AgentConsoleViewTest extends Base
{
    public function test_page_declares_language_and_a_single_h1(): void
    {
        $html = $this->view()->renderAgentList($this->agents());

        self::assertStringContainsString('<html lang="en">', $html);
        self::assertSame(
            1,
            substr_count($html, '<h1'),
            'A11Y-001: exactly one h1 per page'
        );
    }

    public function test_landmarks_and_a_skip_link_are_present(): void
    {
        $html = $this->view()->renderAgentList($this->agents());

        self::assertStringContainsString('role="banner"', $html);
        self::assertStringContainsString('role="main"', $html);
        self::assertStringContainsString('role="contentinfo"', $html);
        self::assertStringContainsString('href="#main"', $html, 'A11Y-002: skip link');
    }

    public function test_the_agent_table_is_captioned_and_has_scoped_headers(): void
    {
        $html = $this->view()->renderAgentList($this->agents());

        self::assertStringContainsString('<caption', $html, 'A11Y-001: table needs a caption');
        self::assertStringContainsString('scope="col"', $html);
    }

    /**
     * A11Y-004: status must not be conveyed by colour alone. The symbol is
     * decorative (aria-hidden) and the real state is text a screen reader reads.
     */
    public function test_status_is_conveyed_by_text_and_a_decorative_symbol(): void
    {
        $html = $this->view()->renderAgentList([
            $this->agent('active-agent', 'active'),
        ]);

        self::assertStringContainsString('aria-hidden="true"', $html, 'the icon must be decorative');
        self::assertMatchesRegularExpression(
            '/<span[^>]*aria-hidden="true"[^>]*>[^<]+<\/span>\s*<span[^>]*class="status-label"[^>]*>active<\/span>/',
            $html,
            'the state must also appear as real text, not only as a glyph'
        );
    }

    /**
     * SEC-010 / SFR-AI-002: untrusted content is DATA. An agent name is
     * attacker-influenced (it comes from a registry row an operator typed), so
     * it must never become markup.
     */
    public function test_a_poisoned_agent_name_is_escaped_not_rendered(): void
    {
        $html = $this->view()->renderAgentList([
            $this->agent('<script>alert(1)</script>', 'active'),
        ]);

        self::assertStringNotContainsString('<script>alert(1)</script>', $html);
        self::assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $html);
    }

    public function test_a_poisoned_attribute_value_cannot_break_out(): void
    {
        $html = $this->view()->renderAgentList([
            $this->agent('x" onmouseover="alert(1)', 'active'),
        ]);

        self::assertStringNotContainsString('onmouseover="alert(1)"', $html);
        self::assertStringContainsString('&quot;', $html, 'ENT_QUOTES must close attribute injection');
    }

    /** SEC-004: the page must not carry inline style or script. */
    public function test_no_inline_style_or_script_is_emitted(): void
    {
        $html = $this->view()->renderAgentList($this->agents());

        self::assertStringNotContainsString('<style', $html, 'inline <style> forces style-src unsafe-inline');
        self::assertStringNotContainsString('<script', $html, 'CSP grants no script-src unsafe-inline');
        self::assertStringNotContainsString(' style="', $html, 'no inline style attributes either');
        self::assertStringNotContainsString(' onclick', $html);
    }

    public function test_the_stylesheet_is_linked_as_a_separate_asset(): void
    {
        $html = $this->view()->renderAgentList($this->agents());

        self::assertStringContainsString(
            '<link rel="stylesheet" href="/assets/console.css">',
            $html,
            'the stylesheet must be served same-origin so style-src can stay self'
        );
    }

    /**
     * WCAG 2.2 SC 3.3.8: the login form must allow password-manager autofill
     * and paste. `autocomplete` on both fields is the mechanism.
     */
    public function test_login_form_allows_password_manager_autofill(): void
    {
        $html = $this->view()->renderLogin();

        self::assertStringContainsString('autocomplete="username"', $html);
        self::assertStringContainsString('autocomplete="current-password"', $html);
        self::assertStringContainsString('type="password"', $html);
        self::assertStringNotContainsString(
            'onpaste',
            $html,
            'WCAG 2.2 SC 3.3.8: paste must not be blocked on a login form'
        );
        self::assertStringNotContainsString('oncopy', $html);
        self::assertStringNotContainsString('onpaste="return false"', $html);
    }

    public function test_login_form_posts_same_origin(): void
    {
        $html = $this->view()->renderLogin();

        // CSP declares form-action 'self', so an off-origin action would be
        // blocked by the browser and the form would silently do nothing.
        self::assertStringContainsString('action="/login"', $html);
        self::assertStringContainsString('method="post"', $html);
        self::assertStringContainsString('type="hidden"', $html, 'the CSRF token field');
    }

    public function test_login_form_has_labelled_fields_and_no_inline_script(): void
    {
        $html = $this->view()->renderLogin();

        self::assertStringContainsString('for="login-email"', $html);
        self::assertStringContainsString('for="login-password"', $html);
        self::assertStringNotContainsString('<script', $html);
        self::assertStringNotContainsString('<style', $html);
    }

    public function test_empty_registry_renders_an_explicit_empty_state(): void
    {
        $html = $this->view()->renderAgentList([]);

        self::assertStringContainsString('No active agents', $html);
        self::assertStringNotContainsString('<tbody></tbody>', $html);
    }

    private function view(): AgentConsoleView
    {
        return new AgentConsoleView();
    }

    /**
     * @return list<array{id: int, name: string, owner: string, purpose: string, risk_class: string, status: string, allowed_tools: list<string>, model_config: array<string, scalar|null>}>
     */
    private function agents(): array
    {
        return [
            $this->agent('lead-analyst', 'active'),
            $this->agent('intake-agent', 'disabled'),
        ];
    }

    /**
     * @return array{id: int, name: string, owner: string, purpose: string, risk_class: string, status: string, allowed_tools: list<string>, model_config: array<string, scalar|null>}
     */
    private function agent(string $name, string $status): array
    {
        return [
            'id' => 1,
            'name' => $name,
            'owner' => 'ops-team',
            'purpose' => 'Classify inbound leads',
            'risk_class' => 'medium',
            'status' => $status,
            'allowed_tools' => ['crm.lookup'],
            'model_config' => ['model' => 'hermes3:8b'],
        ];
    }
}
