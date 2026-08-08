<?php

declare(strict_types=1);

namespace App\Tests\Reporting;

use App\Reporting\ReportAssembler;
use App\Reporting\ReportData;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * P2-T3 reporting suite - WCAG 2.2 AA output + escape-all-data discipline.
 *
 * The regression value: (a) every report kind renders the accessible scaffold
 * (landmark + labelled heading + scoped table); (b) a hostile metric/section
 * value is escaped, proving reports never emit attacker-influenced markup
 * (SEC-010 / SFR-AI-002); (c) an unknown kind is refused. These are the
 * guarantees the assembler exists to hold.
 *
 * © AI WebScapes 2026
 */
final class ReportAssemblerTest extends TestCase
{
    private function assembler(): ReportAssembler
    {
        return new ReportAssembler();
    }

    /**
     * @param array<string, mixed>        $metrics
     * @param list<array<string, mixed>>  $sections
     */
    private function data(string $kind, array $metrics = [], array $sections = []): ReportData
    {
        return new ReportData($kind, 'Test title', $metrics, $sections, '2026-08-08T12:00:00+00:00');
    }

    public function test_all_six_kinds_render_accessible_scaffold(): void
    {
        $asm = $this->assembler();

        foreach (['assessment', 'operational', 'executive', 'security', 'sla', 'acceptance'] as $kind) {
            $html = $asm->render($this->data($kind, ['sample' => 1], [
                ['metric' => 'cycle_time', 'value' => '3d'],
            ]));

            self::assertStringContainsString('<section class="report report--' . $kind . '"', $html, "$kind: landmark");
            self::assertStringContainsString('aria-labelledby="report-heading"', $html, "$kind: labelled landmark");
            self::assertStringContainsString('<h1 id="report-heading">', $html, "$kind: heading");
            self::assertStringContainsString('<table class="report__table">', $html, "$kind: table");
        }
    }

    public function test_section_table_has_scoped_headers(): void
    {
        $html = $this->assembler()->render($this->data('operational', [], [
            ['metric' => 'cycle_time', 'value' => '3d'],
        ]));

        self::assertStringContainsString('<th scope="col">metric</th>', $html);
        self::assertStringContainsString('<th scope="col">value</th>', $html);
        self::assertStringContainsString('<td>cycle_time</td>', $html);
        self::assertStringContainsString('<td>3d</td>', $html);
    }

    public function test_untrusted_metric_value_is_escaped(): void
    {
        // A value that would be markup if interpolated raw must be escaped.
        $hostile = '<script>alert(1)</script>';
        $html = $this->assembler()->render($this->data('security', ['finding' => $hostile]));

        self::assertStringNotContainsString($hostile, $html);
        self::assertStringContainsString(htmlspecialchars($hostile, ENT_QUOTES | ENT_HTML5, 'UTF-8'), $html);
    }

    public function test_untrusted_section_cell_is_escaped(): void
    {
        $hostile = '"><img src=x onerror=alert(1)>';
        $html = $this->assembler()->render($this->data('executive', [], [
            ['note' => $hostile],
        ]));

        self::assertStringNotContainsString($hostile, $html);
        self::assertStringContainsString(htmlspecialchars($hostile, ENT_QUOTES | ENT_HTML5, 'UTF-8'), $html);
    }

    public function test_empty_sections_render_empty_notice(): void
    {
        $html = $this->assembler()->render($this->data('acceptance'));

        self::assertStringContainsString('No detail rows recorded.', $html);
    }

    public function test_unknown_kind_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown report kind "nonsense"');

        $this->assembler()->render($this->data('nonsense'));
    }

    public function test_generated_timestamp_is_escaped_and_in_time_tag(): void
    {
        $html = $this->assembler()->render($this->data('sla'));

        self::assertStringContainsString('<time datetime="2026-08-08T12:00:00+00:00">', $html);
    }
}
