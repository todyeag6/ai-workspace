<?php

declare(strict_types=1);

namespace App\Reporting;

use InvalidArgumentException;

/**
 * Assembles the P2-T3 reporting suite as WCAG 2.2 AA HTML (BRD Table 6:
 * "Accessible dashboards, forms, reports, navigation, status messaging").
 *
 * SIDE-EFFECT FREE, LIKE THE DASHBOARD VIEW. It takes a ReportData value object
 * (already built from real sources by a controller/repository) and returns a
 * string. It holds no PDO, no mailer, no file handle - which is what makes the
 * output shape testable and what stops "just write the file here" from being
 * the shortest path. The caller decides where the HTML goes (save, email,
 * render); this class only shapes it.
 *
 * WHY EVERY FIELD IS HTML-ESCAPED: reports aggregate data from many tenants,
 * models and workflow runs. A metric value, a section row, or a generated title
 * is DATA and is escaped as such (SEC-010 / SFR-AI-002: untrusted content is
 * data, never markup). The assembler never emits a raw interpolated value.
 *
 * WHY ONE CLASS FOR SIX KINDS: the kinds share a rendering contract (title,
 * metric cards, a body table, a generated-at footer) and differ only in copy
 * and which metrics/sections they carry. Splitting into six classes would
 * duplicate the accessible scaffolding; a single dispatch keeps the a11y
 * guarantees in one auditable place. Each kind's heading text is explicit so
 * the rendered report names itself.
 *
 * THE SIX PLATFORM KINDS map to the baseline:
 *   assessment  - AI Opportunity & Readiness Assessment (BR-6.1, OBJ-08)
 *   operational - BRD Table 4 "Operational" KPIs + Table 2 operational control
 *   executive   - business-owner summary (BR-11.1 ownership, §10 improve)
 *   security    - BRD Table 4 "Security" KPIs + BR-12.4 release gate
 *   sla         - managed-services SLA-based support (BR-10.1, Table 2)
 *   acceptance  - defined acceptance criteria / test evidence (BR-12.4, EV-*)
 *
 * THE SIX SECURITY-AGENT KINDS (P3-T8) map to 07 Defensive AI Security Agent
 * FRD §2, Reporting: "Executive, technical, compliance mapping, trend,
 * acceptance and retest reports." They are built by
 * App\SecurityAgent\SecurityReportBuilder and rendered here.
 *
 * WHY THEY ARE NAMESPACED `security_*` RATHER THAN REUSING THE KINDS ABOVE.
 * Two words collide across the two baselines and mean DIFFERENT things:
 *   - `executive` above is a business-owner summary (BR-11.1); the FRD's is an
 *     executive RISK report over security findings (06 BRD §6).
 *   - `acceptance` above is BR-12.4 acceptance-criteria / test evidence; the
 *     FRD's is the SBR-5.3 exception and RISK-ACCEPTANCE register.
 * Folding either pair together would silently merge two unrelated reports —
 * a client reading "Acceptance Report" would have no way to tell whether they
 * were looking at release evidence or at waived security risk. Distinct kinds
 * keep both readable, and leave the shipped P2-T3 suite untouched.
 *
 * © AI WebScapes 2026
 */
final class ReportAssembler
{
    private const KINDS = [
        // P2-T3 platform suite.
        'assessment',
        'operational',
        'executive',
        'security',
        'sla',
        'acceptance',
        // P3-T8 defensive security agent suite (07 FRD §2).
        'security_executive',
        'security_technical',
        'security_compliance',
        'security_trend',
        'security_acceptance',
        'security_retest',
    ];

    private const KIND_HEADING = [
        'assessment' => 'AI Opportunity & Readiness Assessment',
        'operational' => 'Operational Report',
        'executive' => 'Executive Report',
        'security' => 'Security Report',
        'sla' => 'Service Level Agreement Report',
        'acceptance' => 'Acceptance Report',
        'security_executive' => 'Executive Risk Report',
        'security_technical' => 'Technical Findings Report',
        'security_compliance' => 'Compliance Mapping Report',
        'security_trend' => 'Trend and Posture Report',
        'security_acceptance' => 'Exception and Risk Acceptance Register',
        'security_retest' => 'Retest Report',
    ];

    public function render(ReportData $data): string
    {
        if (!in_array($data->kind, self::KINDS, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown report kind "%s". Allowed: %s.',
                $data->kind,
                implode(', ', self::KINDS)
            ));
        }

        $heading = self::KIND_HEADING[$data->kind];
        $title = $this->esc($data->title);
        $generated = $this->esc($data->generatedAt);

        $metrics = $this->renderMetrics($data->metrics);
        $body = $this->renderSections($data->sections);

        return <<<HTML
<section class="report report--{$data->kind}" aria-labelledby="report-heading">
  <header class="report__header">
    <h1 id="report-heading">{$this->esc($heading)}</h1>
    <p class="report__title">{$title}</p>
    <p class="report__generated"><time datetime="{$generated}">Generated {$generated}</time></p>
  </header>
  <div class="report__metrics">
    <h2>Key metrics</h2>
    {$metrics}
  </div>
  <div class="report__body">
    <h2>Details</h2>
    {$body}
  </div>
</section>
HTML;
    }

    /**
     * @param array<string, mixed> $metrics
     */
    private function renderMetrics(array $metrics): string
    {
        if ($metrics === []) {
            return '<p class="report__empty">No metrics recorded.</p>';
        }

        $rows = '';
        foreach ($metrics as $key => $value) {
            $rows .= sprintf(
                '<div class="metric"><span class="metric__label">%s</span><span class="metric__value">%s</span></div>',
                $this->esc((string) $key),
                $this->esc($this->scalar($value))
            );
        }

        return '<dl class="report__metrics-list">' . $rows . '</dl>';
    }

    /**
     * @param list<array<string, mixed>> $sections
     */
    private function renderSections(array $sections): string
    {
        if ($sections === []) {
            return '<p class="report__empty">No detail rows recorded.</p>';
        }

        $headerCells = '';
        $first = $sections[0];
        foreach (array_keys($first) as $col) {
            $headerCells .= sprintf('<th scope="col">%s</th>', $this->esc((string) $col));
        }

        $bodyRows = '';
        foreach ($sections as $row) {
            $cells = '';
            foreach (array_keys($first) as $col) {
                $cells .= sprintf('<td>%s</td>', $this->esc($this->scalar($row[$col] ?? '')));
            }
            $bodyRows .= '<tr>' . $cells . '</tr>';
        }

        return <<<HTML
<table class="report__table">
  <thead><tr>{$headerCells}</tr></thead>
  <tbody>{$bodyRows}</tbody>
</table>
HTML;
    }

    private function scalar(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_array($value)) {
            return '[' . implode(', ', array_map($this->scalar(...), $value)) . ']';
        }
        return (string) $value;
    }

    private function esc(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}
