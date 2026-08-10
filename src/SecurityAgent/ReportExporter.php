<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Audit\AuditLogger;
use App\Reporting\ReportAssembler;
use App\Reporting\ReportData;
use RuntimeException;

/**
 * The Reporting component's acting half: renders a built report and records
 * the export as an audited event.
 *
 * THE REQUIREMENT THIS EXISTS TO SATISFY, VERBATIM
 * -------------------------------------------------
 * SFR-AUD-001 [Must]: "All scope, scan, finding, severity, assignment,
 * exception, export, and retest changes shall be audited."
 *
 * EXPORT is in that list, between exception and retest. An export is not a
 * read — it is the moment security findings leave the platform's control and
 * become a file somebody can forward. That is precisely the event an audit
 * trail exists to record, and it is the one event a reporting component is
 * uniquely placed to witness.
 *
 * WHY THIS IS A SEPARATE CLASS FROM SecurityReportBuilder
 * --------------------------------------------------------
 * Same decider/actor seam used throughout this module (ScopeManager vs
 * ScanRepository, RemediationTracker vs RemediationRepository). The builder is
 * pure and therefore trivially testable; this class holds the AuditLogger and
 * is the ONLY path from a ReportData to a rendered string that a caller is
 * meant to use. Keeping them apart means "was this export audited?" has one
 * answer in one place, rather than depending on which of six build methods a
 * caller happened to call.
 *
 * WHY IT FAILS CLOSED WITHOUT AN AuditLogger
 * -------------------------------------------
 * Identical to RemediationRepository::requireAudit() and
 * FindingRepository::requireAudit(): an export nobody can evidence is not an
 * export this class will perform. A nullable logger that silently skips the
 * write would make the audit requirement optional in practice — always off in
 * exactly the deployment that most needs it. So the logger is required at the
 * moment of export, and its absence throws.
 *
 * WHY THE AUDIT ROW IS WRITTEN BEFORE THE HTML IS RETURNED
 * ---------------------------------------------------------
 * The same idempotency-before-effect discipline the orchestrator uses
 * (FR-ORCH-002): claim the record first, then produce the artefact. If the
 * audit write fails, the exception propagates and no report string is ever
 * handed to the caller — so there is no code path that produces an exportable
 * artefact without the row that says who took it.
 *
 * WHAT THE AUDIT ROW DELIBERATELY DOES NOT CONTAIN
 * -------------------------------------------------
 * Not the report body. SFR-AUTH-003 forbids credentials in reports OR LOGS,
 * and the cheapest way to honour that in an audit trail is to record the
 * report's identity (kind, title, row count, a content digest) rather than its
 * contents. The digest still makes the export evidential: an exported file can
 * be matched to its audit row without the row itself becoming a second copy of
 * the data. AuditLogger redacts credential-shaped values on top of that
 * (FR-AUD-002), which is defence in depth, not the primary control.
 *
 * © AI WebScapes 2026
 */
final class ReportExporter
{
    /** The SFR-AUD-001 "export" event. */
    public const AUDIT_EXPORT = 'security.report.export';

    private const AUDIT_SOURCE = 'report_exporter';

    private const AUDIT_OBJECT_TYPE = 'security_report';

    private ReportAssembler $assembler;

    private ?AuditLogger $audit;

    /**
     * @param AuditLogger|null $audit Required at export time; see the class
     *                                comment for why its absence throws
     *                                rather than skipping the row.
     */
    public function __construct(?AuditLogger $audit = null, ?ReportAssembler $assembler = null)
    {
        $this->assembler = $assembler ?? new ReportAssembler();
        $this->audit = $audit;
    }

    /**
     * Renders a report to accessible HTML and audits the export.
     *
     * @param int         $tenantId     The tenant the report belongs to.
     * @param ReportData  $report       Built by SecurityReportBuilder, which
     *                                  has already applied the redaction and
     *                                  cross-tenant gates.
     * @param string      $exportedBy   The named human or system taking the
     *                                  export. Refused when empty: an export
     *                                  with no actor is unattributable, which
     *                                  makes the audit row worthless.
     * @param int|null    $actorUserId  The platform user id, when known.
     * @param string|null $correlationId Ties this export to a wider operation.
     *
     * @return string The rendered, WCAG 2.2 AA report HTML.
     */
    public function export(
        int $tenantId,
        ReportData $report,
        string $exportedBy,
        ?int $actorUserId = null,
        ?string $correlationId = null
    ): string {
        if (trim($exportedBy) === '') {
            throw new RuntimeException(
                'An export must name who took it (SFR-AUD-001). An unattributable export '
                . 'cannot be audited, so it is refused.'
            );
        }

        // Rendered first so the digest describes exactly what left the
        // platform - but nothing is RETURNED until the audit row lands.
        $html = $this->assembler->render($report);

        $this->requireAudit()->record(
            $tenantId,
            $actorUserId,
            self::AUDIT_EXPORT,
            self::AUDIT_OBJECT_TYPE,
            $report->kind,
            'success',
            self::AUDIT_SOURCE,
            $correlationId,
            [],
            [
                'kind' => $report->kind,
                'title' => $report->title,
                'rows' => count($report->sections),
                'generated_at' => $report->generatedAt,
                // Identity, not contents. See the class comment.
                'content_sha256' => hash('sha256', $html),
                'exported_by' => $exportedBy,
            ],
            sprintf('Exported %s report (%d rows)', $report->kind, count($report->sections))
        );

        return $html;
    }

    /**
     * @throws RuntimeException When no AuditLogger was supplied.
     */
    private function requireAudit(): AuditLogger
    {
        if ($this->audit === null) {
            // SFR-AUD-001 names export as an auditable event, and an export
            // nobody can evidence is not one this class will perform.
            throw new RuntimeException(
                'ReportExporter needs an AuditLogger: SFR-AUD-001 requires every export to be '
                . 'audited, so an unaudited export is refused rather than performed silently.'
            );
        }

        return $this->audit;
    }
}
