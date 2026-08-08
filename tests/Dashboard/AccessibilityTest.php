<?php

declare(strict_types=1);

namespace App\Tests\Dashboard;

use App\Dashboard\DashboardController;
use App\Dashboard\DashboardView;
use PHPUnit\Framework\TestCase;
use PDO;

/**
 * P1-T15 automated accessibility assertions (A11Y-002/003/004, FR-DASH-002).
 *
 * Pure markup tests - they render the dashboard HTML and assert the WCAG 2.2 AA
 * guarantees a manual pass (A11Y-006) then confirms. No DB: the markup is a pure
 * function of the DashboardView, so the presentation guarantees are unit-testable
 * in isolation. (The real data still flows through the tenant-scoped repository;
 * this class only proves the rendered tree.)
 */
final class AccessibilityTest extends TestCase
{
    private DashboardController $controller;

    protected function setUp(): void
    {
        // The controller renders pure HTML; no live PDO is required for the
        // markup assertions, but the constructor demands one - pass a throwaway
        // so the shape tests stay fast and DB-free.
        $this->controller = new DashboardController(
            new PDO('sqlite::memory:'),
            1,
            'staff'
        );
    }

    /**
     * A11Y-004 / FR-DASH-002 - a status is conveyed by text AND shape, never by
     * colour alone. The icon is aria-hidden (decorative); the label text carries
     * the meaning, and a numeric count backs it.
     */
    public function test_status_not_color_only(): void
    {
        $html = $this->dashboardHtml('staff');

        // Every pipeline row carries a visible status LABEL (text), not just a
        // colour. If colour were the only signal, there would be no label text.
        self::assertStringContainsString('>New<', $html);
        self::assertStringContainsString('>Review<', $html);
        self::assertStringContainsString('>Converted<', $html);

        // The icon is explicitly decorative so a colour/shape cannot become the
        // sole carrier of meaning for AT.
        self::assertStringContainsString('aria-hidden="true"', $html);

        // A programmatically determinable count cell exists per state.
        self::assertGreaterThanOrEqual(5, substr_count($html, 'class="count"'));
    }

    /**
     * A11Y-002 - the page has a single main landmark and is keyboard-navigable:
     * native controls, no autofocus trap, and visible focus styling is declared.
     */
    public function test_all_controls_keyboard_operable(): void
    {
        $html = $this->dashboardHtml('staff');

        self::assertHasRole($html, 'main');
        self::assertHasRole($html, 'banner');
        self::assertHasRole($html, 'contentinfo');

        // No keyboard trap: there must be no autofocus attribute that would pin
        // focus, and the form submits via a real <button type="submit">.
        self::assertStringNotContainsString('autofocus', $html);
        self::assertStringContainsString('<button type="submit"', $html);

        // A11Y-002 (carried-over deck fix): focus is visibly styled.
        self::assertVisibleFocusStyles($html);
    }

    /**
     * A11Y-003 - form errors are programmatically determinable: the invalid
     * field is flagged aria-invalid and linked via aria-describedby to a
     * role="alert" message.
     */
    public function test_form_errors_programmatically_determinable(): void
    {
        $html = $this->leadFormHtml(invalid: true);

        self::assertStringContainsString('aria-invalid="true"', $html);
        self::assertStringContainsString('role="alert"', $html);
        self::assertStringContainsString('aria-describedby', $html);

        // A11Y-003 - the error is programmatically linked: the field's
        // aria-describedby points at a real, role="alert" element. Asserting the
        // referenced id exists is what makes the linkage machine-determinable
        // rather than decorative.
        self::assertStringContainsString('aria-describedby="lead-email-hint email-error"', $html);
        self::assertStringContainsString('id="email-error"', $html);
        self::assertStringContainsString('id="lead-email-hint"', $html);
    }

    /**
     * A11Y-001 - perceivable: a single <h1>, a document language, and a <title>.
     */
    public function test_page_is_perceivable(): void
    {
        $html = $this->dashboardHtml('staff');

        self::assertSame(1, substr_count($html, '<h1'));
        self::assertStringContainsString('<html lang="en">', $html);
        self::assertStringContainsString('<title>', $html);
        // Skip link gives keyboard users a direct path past the banner.
        self::assertStringContainsString('Skip to main content', $html);
    }

    private function dashboardHtml(string $role): string
    {
        $view = new DashboardView(
            ['New' => 0, 'Review' => 0, 'Qualified' => 0, 'Disqualified' => 0, 'Converted' => 0],
            [],
            []
        );

        return $this->controller->renderHtml($view, $role);
    }

    private function leadFormHtml(bool $invalid): string
    {
        return $this->controller->leadFormHtml($invalid ? ['email' => 'Enter a valid email address.'] : []);
    }

    private function assertHasRole(string $html, string $role): void
    {
        self::assertStringContainsString('role="' . $role . '"', $html, "Missing landmark role=\"{$role}\".");
    }

    private function assertVisibleFocusStyles(string $html): void
    {
        self::assertStringContainsString(':focus-visible', $html, 'No visible focus styling declared (A11Y-002).');
    }
}
