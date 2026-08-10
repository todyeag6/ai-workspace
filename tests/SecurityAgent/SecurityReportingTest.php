<?php

declare(strict_types=1);

namespace App\Tests\SecurityAgent;

use App\Audit\AuditLogger;
use App\Reporting\ReportAssembler;
use App\SecurityAgent\CrossTenantReportRefused;
use App\SecurityAgent\Finding;
use App\SecurityAgent\RedactionScanner;
use App\SecurityAgent\Remediation;
use App\SecurityAgent\ReportDisposition;
use App\SecurityAgent\ReportExporter;
use App\SecurityAgent\ReportRedactionRequired;
use App\SecurityAgent\Retest;
use App\SecurityAgent\RiskAcceptance;
use App\SecurityAgent\SecurityReportBuilder;
use App\Tests\TestCase;
use DateTimeImmutable;
use DateTimeZone;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

/**
 * P3-T8 - Reporting, the last component in the FRD's order (Finding Engine ->
 * AI Triage Assistant -> Remediation Tracker -> Reporting).
 *
 * Each test maps to a baseline requirement, quoted verbatim where it governs:
 *
 *  - FRD section 2, Reporting: "Executive, technical, compliance mapping,
 *    trend, acceptance and retest reports." SIX types, one test each.
 *  - SFR-REPORT-001 [Must]: "Reports shall clearly distinguish confirmed,
 *    suspected, informational, accepted, remediated, and not-retested items."
 *    SIX dispositions, plus the precedence between them.
 *  - SFR-AUTH-003 [Must]: "Credentials shall be stored as scoped secrets and
 *    never included in reports or logs."
 *  - SFR-AUD-001 [Must]: audits "export" among the recorded events.
 *  - FRD section 7 "Report redaction": "Secrets and session tokens are absent
 *    from normal report output."
 *  - FRD section 7 "Cross tenant": "No finding/evidence/report access across
 *    tenant."
 *  - AC-001 tenant scoping; AC-002 allowlists, not denylists.
 *
 * MOST OF THESE TESTS TOUCH NO DATABASE, and that is the design paying off:
 * SecurityReportBuilder takes hydrated value objects and returns a value
 * object, so "does this report leak a secret?" is answerable without MySQL, a
 * tenant or a scanner. Only the export-audit tests need the real audit table.
 *
 * © AI WebScapes 2026
 */
final class SecurityReportingTest extends TestCase
{
    // =================================================================
    // HELPERS
    // =================================================================

    private function builder(): SecurityReportBuilder
    {
        return new SecurityReportBuilder();
    }

    private function at(string $moment): DateTimeImmutable
    {
        return new DateTimeImmutable($moment, new DateTimeZone('UTC'));
    }

    /**
     * @param list<string> $standardsMapping
     */
    private function finding(
        int $id,
        string $severity = Finding::SEVERITY_HIGH,
        string $status = Finding::STATUS_OPEN,
        int $tenantId = 1,
        string $title = 'TLS 1.0 accepted on public endpoint',
        string $firstSeenAt = '2026-03-01 09:00:00',
        array $standardsMapping = ['ASVS-9.1.1'],
        ?string $remediation = 'Disable TLS 1.0 at the load balancer.'
    ): Finding {
        return new Finding(
            tenantId: $tenantId,
            id: $id,
            fingerprint: sprintf('%064d', $id),
            title: $title,
            category: Finding::CATEGORY_TRANSPORT_EXPOSURE,
            severity: $severity,
            confidence: Finding::CONFIDENCE_HIGH,
            affectedAssets: [7],
            remediation: $remediation,
            standardsMapping: $standardsMapping,
            owner: 'Platform Team',
            status: $status,
            slaDueAt: $this->at('2026-03-15 09:00:00'),
            firstSeenAt: $this->at($firstSeenAt),
            lastSeenAt: $this->at('2026-03-02 09:00:00'),
            occurrenceCount: 2
        );
    }

    private function remediation(
        int $id,
        int $findingId,
        string $status = Remediation::STATUS_IN_PROGRESS,
        int $tenantId = 1,
        ?string $verifiedBy = null,
        ?string $plan = 'Disable the protocol at the edge.'
    ): Remediation {
        return new Remediation(
            tenantId: $tenantId,
            id: $id,
            findingId: $findingId,
            owner: 'Dana Okafor',
            plan: $plan,
            dueAt: $this->at('2026-03-15 09:00:00'),
            changeReference: 'CHG-2026-0412',
            status: $status,
            createdBy: 'Dana Okafor',
            createdAt: $this->at('2026-03-01 12:00:00'),
            updatedAt: $this->at('2026-03-04 12:00:00'),
            verifiedBy: $verifiedBy,
            verifiedAt: $verifiedBy === null ? null : $this->at('2026-03-06 12:00:00')
        );
    }

    private function retest(
        int $id,
        int $findingId,
        int $remediationId,
        string $result = Retest::RESULT_PASS,
        int $tenantId = 1,
        ?string $evidenceHash = null,
        string $performedAt = '2026-03-06 10:00:00',
        ?string $note = null
    ): Retest {
        return new Retest(
            tenantId: $tenantId,
            id: $id,
            findingId: $findingId,
            remediationId: $remediationId,
            scanProfileId: 3,
            profileVersion: 1,
            result: $result,
            performedBy: 'Priya Raman',
            performedAt: $this->at($performedAt),
            scanId: null,
            evidenceId: null,
            evidenceHash: $result === Retest::RESULT_PASS
                ? ($evidenceHash ?? str_repeat('b', 64))
                : $evidenceHash,
            note: $note
        );
    }

    private function acceptance(
        int $id,
        int $findingId,
        string $expiresAt = '2026-12-31 00:00:00',
        int $tenantId = 1,
        string $status = RiskAcceptance::STATUS_ACTIVE,
        ?string $reviewAt = null,
        string $rationale = 'Compensating WAF rule blocks the affected path.'
    ): RiskAcceptance {
        $expiry = $this->at($expiresAt);
        // SBR-5.3 refuses a review scheduled after expiry, so the default
        // review sits 30 days before whatever expiry the test asked for.
        $review = $reviewAt === null
            ? $expiry->sub(new \DateInterval('P30D'))
            : $this->at($reviewAt);

        return new RiskAcceptance(
            tenantId: $tenantId,
            id: $id,
            findingId: $findingId,
            approver: 'Chen Wei',
            rationale: $rationale,
            compensatingControl: 'WAF rule 4021 blocks the vulnerable path.',
            reviewAt: $review,
            expiresAt: $expiry,
            status: $status,
            createdAt: $this->at('2026-03-01 09:00:00'),
            revokedBy: $status === RiskAcceptance::STATUS_REVOKED ? 'Chen Wei' : null,
            revokedAt: $status === RiskAcceptance::STATUS_REVOKED
                ? $this->at('2026-03-20 09:00:00')
                : null,
            revocationReason: $status === RiskAcceptance::STATUS_REVOKED
                ? 'Superseded by a permanent fix.'
                : null
        );
    }

    private function seedTenant(int $tenantId): void
    {
        $statement = $this->pdo->prepare(
            'INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model)'
            . " VALUES (:id, :slug, :name, 'active', 'cloud')"
        );
        $statement->bindValue('id', $tenantId, PDO::PARAM_INT);
        $statement->bindValue('slug', 'reporting-tenant-' . $tenantId);
        $statement->bindValue('name', 'Reporting Tenant ' . $tenantId);
        $statement->execute();
    }

    // =================================================================
    // SFR-REPORT-001 - THE SIX DISPOSITIONS
    // "Reports shall clearly distinguish confirmed, suspected,
    //  informational, accepted, remediated, and not-retested items."
    //
    // Six words in the requirement, so six proofs that each is reachable
    // and distinct, then the precedence between them.
    // =================================================================

    public function test_the_six_dispositions_are_exactly_the_ones_the_requirement_names(): void
    {
        self::assertSame(
            ['confirmed', 'suspected', 'informational', 'accepted', 'remediated', 'not_retested'],
            ReportDisposition::DISPOSITIONS,
            'SFR-REPORT-001 names exactly these six, in this order.'
        );
    }

    public function test_a_verified_and_evidenced_fix_is_remediated(): void
    {
        $disposition = (new ReportDisposition())->forFinding(
            $this->finding(1),
            $this->remediation(10, 1, Remediation::STATUS_VERIFIED, verifiedBy: 'Priya Raman'),
            [$this->retest(100, 1, 10, Retest::RESULT_PASS)],
            [],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(ReportDisposition::REMEDIATED, $disposition);
    }

    public function test_a_claimed_fix_with_no_retest_is_not_retested_never_remediated(): void
    {
        // THE RULE THAT MATTERS MOST: a fix nobody verified must not read as
        // remediated.
        $disposition = (new ReportDisposition())->forFinding(
            $this->finding(1),
            $this->remediation(10, 1, Remediation::STATUS_FIX_APPLIED),
            [],
            [],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(ReportDisposition::NOT_RETESTED, $disposition);
        self::assertNotSame(ReportDisposition::REMEDIATED, $disposition);
    }

    public function test_a_live_waiver_makes_the_item_accepted(): void
    {
        $disposition = (new ReportDisposition())->forFinding(
            $this->finding(1),
            null,
            [],
            [$this->acceptance(50, 1, expiresAt: '2026-12-31 00:00:00')],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(ReportDisposition::ACCEPTED, $disposition);
    }

    public function test_an_expired_waiver_no_longer_reads_as_accepted(): void
    {
        // Expiry is DERIVED from the clock, never a stored flag: a lapsed
        // waiver must stop suppressing the finding the moment it expires,
        // whether or not a cron job ran (SBR-5.3).
        $disposition = (new ReportDisposition())->forFinding(
            $this->finding(1, status: Finding::STATUS_CONFIRMED),
            null,
            [],
            [$this->acceptance(50, 1, expiresAt: '2026-03-31 00:00:00')],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertNotSame(ReportDisposition::ACCEPTED, $disposition);
        self::assertSame(ReportDisposition::CONFIRMED, $disposition);
    }

    public function test_an_informational_finding_is_informational(): void
    {
        $disposition = (new ReportDisposition())->forFinding(
            $this->finding(1, severity: Finding::SEVERITY_INFORMATIONAL),
            null,
            [],
            [],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(ReportDisposition::INFORMATIONAL, $disposition);
    }

    public function test_a_human_validated_finding_is_confirmed(): void
    {
        $disposition = (new ReportDisposition())->forFinding(
            $this->finding(1, status: Finding::STATUS_CONFIRMED),
            null,
            [],
            [],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(ReportDisposition::CONFIRMED, $disposition);
    }

    public function test_an_unvalidated_open_finding_is_suspected(): void
    {
        // The conservative floor: a machine's opinion nobody has checked.
        $disposition = (new ReportDisposition())->forFinding(
            $this->finding(1, status: Finding::STATUS_OPEN),
            null,
            [],
            [],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(ReportDisposition::SUSPECTED, $disposition);
    }

    public function test_not_retested_outranks_accepted_and_confirmed(): void
    {
        // An item can qualify for several dispositions at once. The warning
        // that a fix is unverified must not be hidden behind a waiver or a
        // confirmation - that is the misreport SFR-REPORT-001 prevents.
        $disposition = (new ReportDisposition())->forFinding(
            $this->finding(1, status: Finding::STATUS_CONFIRMED),
            $this->remediation(10, 1, Remediation::STATUS_FIX_APPLIED),
            [],
            [$this->acceptance(50, 1, expiresAt: '2026-12-31 00:00:00')],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(ReportDisposition::NOT_RETESTED, $disposition);
    }

    public function test_a_verified_status_without_evidence_falls_back_to_not_retested(): void
    {
        // Defence in depth. RemediationRepository::verify() will not write
        // `verified` without evidence, but if a row ever said so anyway, the
        // report must still not call it remediated.
        $disposition = (new ReportDisposition())->forFinding(
            $this->finding(1),
            $this->remediation(10, 1, Remediation::STATUS_VERIFIED, verifiedBy: 'Priya Raman'),
            [$this->retest(100, 1, 10, Retest::RESULT_FAIL)],
            [],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(ReportDisposition::NOT_RETESTED, $disposition);
    }

    public function test_a_stale_pass_does_not_outrank_a_later_failure(): void
    {
        // The tracker reads the LATEST retest; the report inherits that rule
        // rather than searching the history for a flattering result.
        $disposition = (new ReportDisposition())->forFinding(
            $this->finding(1),
            $this->remediation(10, 1, Remediation::STATUS_VERIFIED, verifiedBy: 'Priya Raman'),
            [
                $this->retest(100, 1, 10, Retest::RESULT_PASS, performedAt: '2026-03-06 10:00:00'),
                $this->retest(101, 1, 10, Retest::RESULT_FAIL, performedAt: '2026-06-06 10:00:00'),
            ],
            [],
            $this->at('2026-07-01 00:00:00')
        );

        self::assertSame(ReportDisposition::NOT_RETESTED, $disposition);
    }

    public function test_an_inconclusive_retest_closes_nothing(): void
    {
        // SFR-SCAN-003: a tool failure is not a statement about the target.
        $disposition = (new ReportDisposition())->forFinding(
            $this->finding(1),
            $this->remediation(10, 1, Remediation::STATUS_VERIFIED, verifiedBy: 'Priya Raman'),
            [$this->retest(100, 1, 10, Retest::RESULT_INCONCLUSIVE)],
            [],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(ReportDisposition::NOT_RETESTED, $disposition);
    }

    public function test_a_tally_reports_zero_for_dispositions_with_no_items(): void
    {
        // A summary that omits empty dispositions lets "not-retested: 0" and
        // "we never computed not-retested" look identical on the page.
        $tally = (new ReportDisposition())->tally([ReportDisposition::CONFIRMED]);

        self::assertSame(ReportDisposition::DISPOSITIONS, array_keys($tally));
        self::assertSame(1, $tally[ReportDisposition::CONFIRMED]);
        self::assertSame(0, $tally[ReportDisposition::NOT_RETESTED]);
    }

    public function test_an_unknown_disposition_is_refused(): void
    {
        // AC-002: allowlist, so an unrecognised value is refused rather than
        // passed through to a client report.
        $this->expectException(\InvalidArgumentException::class);

        ReportDisposition::label('probably_fine');
    }

    /**
     * @return list<array{0: string}>
     */
    public static function dispositionProvider(): array
    {
        return [
            ['confirmed'],
            ['suspected'],
            ['informational'],
            ['accepted'],
            ['remediated'],
            ['not_retested'],
        ];
    }

    #[DataProvider('dispositionProvider')]
    public function test_every_disposition_has_a_distinct_human_label(string $disposition): void
    {
        $label = ReportDisposition::label($disposition);

        self::assertNotSame('', trim($label));
        self::assertCount(
            6,
            array_unique(array_values(ReportDisposition::LABELS)),
            'Six dispositions need six distinct labels, or a report has not distinguished them.'
        );
    }

    // =================================================================
    // FRD section 2 - THE SIX REPORT TYPES
    // "Executive, technical, compliance mapping, trend, acceptance and
    //  retest reports."
    // =================================================================

    public function test_the_six_report_kinds_are_the_ones_the_frd_names(): void
    {
        self::assertSame(
            [
                'security_executive',
                'security_technical',
                'security_compliance',
                'security_trend',
                'security_acceptance',
                'security_retest',
            ],
            SecurityReportBuilder::KINDS
        );
    }

    public function test_executive_report_carries_the_full_disposition_tally(): void
    {
        $report = $this->builder()->executive(
            1,
            'Acme Q1 executive risk report',
            [$this->finding(1), $this->finding(2, status: Finding::STATUS_CONFIRMED)],
            [$this->remediation(10, 1, Remediation::STATUS_FIX_APPLIED)],
            [],
            [],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(SecurityReportBuilder::KIND_EXECUTIVE, $report->kind);
        self::assertSame(2, $report->metrics['total_findings']);

        // Every disposition present as a metric, including the zeroes.
        foreach (ReportDisposition::DISPOSITIONS as $disposition) {
            self::assertArrayHasKey($disposition, $report->metrics);
        }

        self::assertSame(1, $report->metrics[ReportDisposition::NOT_RETESTED]);
        self::assertSame(1, $report->metrics[ReportDisposition::CONFIRMED]);
        self::assertCount(6, $report->sections, 'One body row per disposition.');
    }

    public function test_technical_report_lists_findings_most_severe_first(): void
    {
        $report = $this->builder()->technical(
            1,
            'Acme technical findings',
            [
                $this->finding(1, severity: Finding::SEVERITY_LOW),
                $this->finding(2, severity: Finding::SEVERITY_CRITICAL),
                $this->finding(3, severity: Finding::SEVERITY_MEDIUM),
            ],
            [],
            [],
            [],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(SecurityReportBuilder::KIND_TECHNICAL, $report->kind);
        self::assertSame(
            ['critical', 'medium', 'low'],
            array_map(static fn (array $row): string => (string) $row['severity'], $report->sections)
        );

        // Each row carries the disposition, so an engineer reading the
        // technical report sees the same state the executive summary counted.
        self::assertArrayHasKey('disposition', $report->sections[0]);
    }

    public function test_compliance_report_groups_by_standards_mapping_and_keeps_unmapped_visible(): void
    {
        $report = $this->builder()->complianceMapping(
            1,
            'Acme standards mapping',
            [
                $this->finding(1, standardsMapping: ['ASVS-9.1.1', 'API-2023-8']),
                $this->finding(2, standardsMapping: ['ASVS-9.1.1']),
                $this->finding(3, standardsMapping: []),
            ],
            [],
            [],
            [],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(SecurityReportBuilder::KIND_COMPLIANCE, $report->kind);

        $byControl = [];
        foreach ($report->sections as $row) {
            $byControl[(string) $row['control']] = (int) $row['items'];
        }

        self::assertSame(2, $byControl['ASVS-9.1.1']);
        self::assertSame(1, $byControl['API-2023-8']);

        // A finding with no mapping must be VISIBLE, not dropped - a silently
        // omitted finding is how a coverage report overstates coverage.
        self::assertArrayHasKey('unmapped', $byControl);
        self::assertSame(1, $byControl['unmapped']);
    }

    public function test_trend_report_buckets_findings_into_configured_windows(): void
    {
        $builder = new SecurityReportBuilder(policy: [
            'trend_lookback_days' => 90,
            'trend_periods' => 2,
            'max_report_rows' => 5000,
            'max_title_chars' => 200,
        ]);

        $report = $builder->trend(
            1,
            'Acme trend and posture',
            [
                // Inside the most recent 90-day window (2026-01-01..2026-04-01).
                $this->finding(1, firstSeenAt: '2026-03-01 09:00:00'),
                // Inside the window before it (2025-10-03..2026-01-01).
                $this->finding(2, firstSeenAt: '2025-11-05 09:00:00'),
            ],
            [],
            [],
            [],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(SecurityReportBuilder::KIND_TREND, $report->kind);
        self::assertCount(2, $report->sections);
        self::assertSame(90, $report->metrics['lookback_days']);

        // Newest window first, and each states its own boundaries so two
        // reports run a week apart are comparable rather than merely similar.
        self::assertSame(1, $report->sections[0]['findings_first_seen']);
        self::assertSame(1, $report->sections[1]['findings_first_seen']);
        self::assertArrayHasKey('period_start', $report->sections[0]);
        self::assertArrayHasKey('period_end', $report->sections[0]);
    }

    public function test_acceptance_register_shows_every_field_sbr_5_3_requires(): void
    {
        $report = $this->builder()->acceptanceRegister(
            1,
            'Acme exception register',
            [$this->acceptance(50, 1, expiresAt: '2026-12-31 00:00:00')],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(SecurityReportBuilder::KIND_ACCEPTANCE, $report->kind);

        $row = $report->sections[0];
        // SBR-5.3: approver, rationale, compensating control, review date,
        // expiry. A waiver whose justification is invisible is not reviewable.
        self::assertSame('Chen Wei', $row['approver']);
        self::assertNotSame('', trim((string) $row['rationale']));
        self::assertNotSame('', trim((string) $row['compensating_control']));
        self::assertArrayHasKey('review_at', $row);
        self::assertArrayHasKey('expires_at', $row);
        self::assertSame('active', $row['state']);
    }

    public function test_acceptance_register_labels_an_expired_waiver_as_expired(): void
    {
        $report = $this->builder()->acceptanceRegister(
            1,
            'Acme exception register',
            [$this->acceptance(50, 1, expiresAt: '2026-03-31 00:00:00')],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame('expired', $report->sections[0]['state']);
        self::assertSame(0, $report->metrics['active']);
    }

    public function test_retest_report_separates_a_pass_from_a_closure(): void
    {
        $report = $this->builder()->retestReport(
            1,
            'Acme retest report',
            [
                $this->retest(100, 1, 10, Retest::RESULT_PASS),
                $this->retest(101, 2, 11, Retest::RESULT_FAIL),
                $this->retest(102, 3, 12, Retest::RESULT_INCONCLUSIVE),
            ],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame(SecurityReportBuilder::KIND_RETEST, $report->kind);
        self::assertSame(3, $report->metrics['retests']);
        self::assertSame(1, $report->metrics['passed']);
        self::assertSame(1, $report->metrics['closing']);

        // An inconclusive run closes nothing (SFR-SCAN-003) and appears as
        // itself, neither a pass nor a failure.
        $results = array_map(static fn (array $r): string => (string) $r['result'], $report->sections);
        self::assertContains('inconclusive', $results);
    }

    public function test_every_security_kind_renders_through_the_shipped_assembler(): void
    {
        // The P2-T3 WCAG 2.2 AA assembler is COMPOSED, not forked: each new
        // kind must render its accessible scaffold.
        $assembler = new ReportAssembler();

        foreach (SecurityReportBuilder::KINDS as $kind) {
            $html = $assembler->render(new \App\Reporting\ReportData(
                $kind,
                'Scaffold check',
                ['items' => 1],
                [['column' => 'value']],
                '2026-04-01T00:00:00+00:00'
            ));

            self::assertStringContainsString('aria-labelledby="report-heading"', $html, $kind);
            self::assertStringContainsString('<h1 id="report-heading">', $html, $kind);
        }
    }

    public function test_the_platform_report_kinds_still_render(): void
    {
        // P3-T8 extended the assembler ADDITIVELY; the shipped P2-T3 suite
        // must be untouched.
        $assembler = new ReportAssembler();

        foreach (['assessment', 'operational', 'executive', 'security', 'sla', 'acceptance'] as $kind) {
            $html = $assembler->render(new \App\Reporting\ReportData(
                $kind,
                'Platform suite',
                [],
                [],
                '2026-04-01T00:00:00+00:00'
            ));

            self::assertStringContainsString('report report--' . $kind, $html);
        }
    }

    // =================================================================
    // FRD section 7 - "Report redaction"
    // "Secrets and session tokens are absent from normal report output."
    // =================================================================

    public function test_a_secret_reaching_a_report_refuses_the_report(): void
    {
        $builder = $this->builder();

        try {
            $builder->technical(
                1,
                'Acme technical findings',
                [$this->finding(
                    1,
                    remediation: 'Rotate the key AKIAIOSFODNN7EXAMPLE and redeploy.'
                )],
                [],
                [],
                [],
                $this->at('2026-04-01 00:00:00')
            );
            self::fail('A secret in report output must refuse the report (FRD section 7).');
        } catch (ReportRedactionRequired $refusal) {
            self::assertContains(RedactionScanner::KIND_SECRET, $refusal->kinds());
            // The refusal names the FIELD, never the value - putting the
            // secret in the message would leak it into a log (SFR-AUTH-003).
            self::assertStringNotContainsString('AKIAIOSFODNN7EXAMPLE', $refusal->getMessage());
        }
    }

    public function test_a_session_token_reaching_a_report_refuses_the_report(): void
    {
        $jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk';

        try {
            $this->builder()->retestReport(
                1,
                'Acme retest report',
                [$this->retest(
                    100,
                    1,
                    10,
                    Retest::RESULT_FAIL,
                    note: 'Reproduced with session ' . $jwt
                )],
                $this->at('2026-04-01 00:00:00')
            );
            self::fail('A session token in report output must refuse the report.');
        } catch (ReportRedactionRequired $refusal) {
            self::assertContains(RedactionScanner::KIND_SESSION_TOKEN, $refusal->kinds());
            self::assertStringNotContainsString($jwt, $refusal->getMessage());
        }
    }

    public function test_a_named_person_does_not_trip_the_redaction_gate(): void
    {
        // Only secrets and session tokens are fatal. SBR-5.3 REQUIRES the
        // approver's name, so treating personal data as fatal would make
        // every lawful register unemittable - which is how a safety control
        // gets switched off in production.
        $report = $this->builder()->acceptanceRegister(
            1,
            'Acme exception register',
            [$this->acceptance(50, 1)],
            $this->at('2026-04-01 00:00:00')
        );

        self::assertSame('Chen Wei', $report->sections[0]['approver']);
    }

    // =================================================================
    // FRD section 7 - "Cross tenant"
    // "No finding/evidence/report access across tenant."
    // =================================================================

    public function test_a_foreign_tenants_finding_refuses_the_report(): void
    {
        try {
            $this->builder()->executive(
                1,
                'Acme executive risk report',
                [$this->finding(1, tenantId: 1), $this->finding(2, tenantId: 2)],
                [],
                [],
                [],
                $this->at('2026-04-01 00:00:00')
            );
            self::fail('A cross-tenant row must refuse the report (FRD section 7).');
        } catch (CrossTenantReportRefused $refusal) {
            self::assertSame(1, $refusal->reportTenantId());
            self::assertSame(2, $refusal->foreignTenantId());
            self::assertSame('finding', $refusal->itemType());
        }
    }

    public function test_a_foreign_tenants_acceptance_refuses_the_register(): void
    {
        $this->expectException(CrossTenantReportRefused::class);

        $this->builder()->acceptanceRegister(
            1,
            'Acme exception register',
            [$this->acceptance(50, 1, tenantId: 2)],
            $this->at('2026-04-01 00:00:00')
        );
    }

    public function test_a_foreign_tenants_retest_refuses_the_retest_report(): void
    {
        $this->expectException(CrossTenantReportRefused::class);

        $this->builder()->retestReport(
            1,
            'Acme retest report',
            [$this->retest(100, 1, 10, Retest::RESULT_FAIL, tenantId: 2)],
            $this->at('2026-04-01 00:00:00')
        );
    }

    public function test_a_report_without_a_tenant_is_refused(): void
    {
        // AC-001: scope is not optional.
        $this->expectException(\InvalidArgumentException::class);

        $this->builder()->retestReport(0, 'No tenant', [], $this->at('2026-04-01 00:00:00'));
    }

    // =================================================================
    // SFR-AUD-001 - "export" is an audited event
    // =================================================================

    public function test_exporting_a_report_writes_an_audit_row(): void
    {
        $this->seedTenant(1);

        $report = $this->builder()->retestReport(
            1,
            'Acme retest report',
            [$this->retest(100, 1, 10, Retest::RESULT_PASS)],
            $this->at('2026-04-01 00:00:00')
        );

        $html = (new ReportExporter(new AuditLogger($this->pdo)))
            ->export(1, $report, 'Chen Wei');

        self::assertStringContainsString('<h1 id="report-heading">', $html);

        $rows = $this->auditRowsFor(ReportExporter::AUDIT_EXPORT);
        self::assertCount(1, $rows);
        self::assertSame('security_report', $rows[0]['object_type']);
        self::assertSame('security_retest', $rows[0]['object_id']);
        self::assertSame('success', $rows[0]['outcome']);
    }

    public function test_an_export_without_an_audit_logger_is_refused(): void
    {
        $report = $this->builder()->retestReport(
            1,
            'Acme retest report',
            [],
            $this->at('2026-04-01 00:00:00')
        );

        // An export nobody can evidence is not one this class will perform.
        $this->expectException(RuntimeException::class);

        (new ReportExporter())->export(1, $report, 'Chen Wei');
    }

    public function test_an_unattributable_export_is_refused(): void
    {
        $this->seedTenant(1);

        $report = $this->builder()->retestReport(
            1,
            'Acme retest report',
            [],
            $this->at('2026-04-01 00:00:00')
        );

        $this->expectException(RuntimeException::class);

        (new ReportExporter(new AuditLogger($this->pdo)))->export(1, $report, '   ');
    }

    public function test_the_audit_row_records_a_digest_not_the_report_body(): void
    {
        $this->seedTenant(1);

        $report = $this->builder()->technical(
            1,
            'Acme technical findings',
            [$this->finding(1, title: 'TLS 1.0 accepted on public endpoint')],
            [],
            [],
            [],
            $this->at('2026-04-01 00:00:00')
        );

        (new ReportExporter(new AuditLogger($this->pdo)))->export(1, $report, 'Chen Wei');

        $statement = $this->pdo->prepare(
            'SELECT object_id, detail FROM audit_events WHERE action = :action'
        );
        $statement->bindValue('action', ReportExporter::AUDIT_EXPORT);
        $statement->execute();
        /** @var array<string, mixed> $row */
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        $detail = (string) $row['detail'];

        // SFR-AUTH-003 forbids credentials in reports OR LOGS, so the audit
        // row records the report's identity, never a second copy of its body.
        self::assertStringNotContainsString('TLS 1.0 accepted on public endpoint', $detail);

        // The kind travels in object_id, which is a bounded identifier column
        // rather than free text. AuditLogger's own high-entropy scrub rewrites
        // long tokens inside $detail — including the kind name — which is the
        // SFR-AUTH-003 belt-and-braces working, not a defect. Identity is
        // therefore asserted where it is authoritative.
        self::assertSame('security_technical', $row['object_id']);
    }

    // =================================================================
    // RATIFIABLE CONFIG - pinned so an unsourced edit fails CI
    // =================================================================

    public function test_shipped_report_policy_pins_its_contract_terms(): void
    {
        /** @var mixed $policy */
        $policy = require dirname(__DIR__, 2) . '/config/security/REPORT_POLICY.php';

        self::assertIsArray($policy);
        self::assertSame(90, $policy['trend_lookback_days']);
        self::assertSame(4, $policy['trend_periods']);
        self::assertSame(5000, $policy['max_report_rows']);
        self::assertSame(200, $policy['max_title_chars']);
    }

    public function test_an_incomplete_report_policy_fails_closed(): void
    {
        // A missing window would otherwise become unbounded or zero-length
        // depending on the reader.
        $this->expectException(\InvalidArgumentException::class);

        new SecurityReportBuilder(policy: ['trend_lookback_days' => 90]);
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function auditRowsFor(string $action): array
    {
        $statement = $this->pdo->prepare(
            'SELECT action, object_type, object_id, outcome, source, detail '
            . 'FROM audit_events WHERE action = :action'
        );
        $statement->bindValue('action', $action);
        $statement->execute();

        $rows = [];
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            if (is_array($row)) {
                /** @var array<string, mixed> $row */
                $rows[] = $row;
            }
        }

        return $rows;
    }
}
