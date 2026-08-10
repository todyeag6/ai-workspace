<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Reporting\ReportData;
use DateInterval;
use DateTimeImmutable;
use InvalidArgumentException;
use RuntimeException;

/**
 * The Reporting component's decision half: builds the six reports FRD
 * section 2 names, from already-hydrated value objects, with no side effects.
 *
 * THE REQUIREMENT THIS EXISTS TO SATISFY, VERBATIM
 * -------------------------------------------------
 * FRD section 2, Reporting row: "Executive, technical, compliance mapping,
 * trend, acceptance and retest reports."
 *
 * Six named report types, and this class builds exactly those six — one public
 * method each, so a missing report is a missing method rather than a string
 * nobody passed. 06 BRD section 6 (Deliverables) corroborates the same set:
 * executive risk report; technical findings with evidence and remediation;
 * standards mapping; trend and posture report for recurring service;
 * exception/risk-acceptance register; retest report.
 *
 * WHY THIS DECIDES AND NEVER ACTS
 * --------------------------------
 * Same decide-not-act split as FindingEngine, ScopeManager, SafetyMonitor,
 * EvidenceProcessor and RemediationTracker: this class holds no PDO, opens no
 * socket, writes no file and reads no clock — the moment is a parameter. It
 * returns a ReportData value object. ReportExporter is the half that renders
 * and audits. That separation is what makes "does this report leak a secret?"
 * answerable in a unit test with no database and no tenant.
 *
 * WHY IT COMPOSES ReportAssembler INSTEAD OF RENDERING
 * -----------------------------------------------------
 * The WCAG 2.2 AA reporting suite already exists (P2-T3): App\Reporting\
 * ReportAssembler escapes every field and emits the accessible scaffold, and
 * App\Reporting\ReportData is its input shape. Rebuilding either here would
 * fork the accessibility guarantees into a second, unreviewed place. This
 * class produces ReportData; the shipped assembler renders it.
 *
 * WHY NOTHING IS RE-DERIVED
 * --------------------------
 * Every fact comes from a sanctioned projection (Finding::toReportArray(),
 * Remediation::toReportArray(), RiskAcceptance::toReportArray(),
 * Retest::toReportArray()) or an existing accessor. Dispositions come from
 * ReportDisposition; closure evidence from RemediationTracker. A rule
 * re-implemented here is a rule that can drift from the one enforced at the
 * write path — and a report that disagrees with the database is worse than no
 * report.
 *
 * THE TWO GUARANTEES EVERY REPORT PASSES THROUGH
 * -----------------------------------------------
 *  1. TENANT (FRD section 7 "Cross tenant"): every value object's tenantId()
 *     must equal the report's tenant, checked before anything is assembled.
 *     The repositories already scope their queries (AC-001), but this class
 *     receives hydrated objects, so it re-checks the one thing still visible
 *     to it. See CrossTenantReportRefused.
 *  2. REDACTION (FRD section 7 "Report redaction", SFR-AUTH-003): every
 *     assembled cell is scanned with RedactionScanner — the same scanner the
 *     evidence layer uses — and a secret or session token REFUSES the report.
 *     See ReportRedactionRequired for why refusing beats scrubbing.
 *
 * Both gates run on the ASSEMBLED output rather than the inputs, because the
 * question worth answering is "what would this report show?", not "what were
 * we handed?".
 *
 * © AI WebScapes 2026
 */
final class SecurityReportBuilder
{
    /** FRD section 2's six report kinds, namespaced for the assembler. */
    public const KIND_EXECUTIVE = 'security_executive';

    public const KIND_TECHNICAL = 'security_technical';

    public const KIND_COMPLIANCE = 'security_compliance';

    public const KIND_TREND = 'security_trend';

    public const KIND_ACCEPTANCE = 'security_acceptance';

    public const KIND_RETEST = 'security_retest';

    /**
     * @var list<string>
     */
    public const KINDS = [
        self::KIND_EXECUTIVE,
        self::KIND_TECHNICAL,
        self::KIND_COMPLIANCE,
        self::KIND_TREND,
        self::KIND_ACCEPTANCE,
        self::KIND_RETEST,
    ];

    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    /**
     * Fields carried into a report body that are FREE TEXT written by a human
     * or captured from a target. These are the cells the redaction gate cares
     * about; an enum or an integer cannot smuggle a token.
     *
     * Kept as an allowlist of what to scan rather than a denylist of what to
     * skip: a new free-text field is scanned by default only if it is added
     * here, so the list is reviewed when the shape changes.
     *
     * @var list<string>
     */
    private const SCANNED_FIELDS = [
        'title',
        'summary',
        'detail',
        'remediation',
        'plan',
        'rationale',
        'compensating_control',
        'note',
        'evidence_hash',
        'change_reference',
        'owner',
        'approver',
        'performed_by',
    ];

    private ReportDisposition $dispositions;

    private RemediationTracker $tracker;

    private RedactionScanner $redaction;

    private int $trendLookbackDays;

    private int $trendPeriods;

    private int $maxRows;

    private int $maxTitleChars;

    /**
     * @param array<string, int>|null $policy Overrides
     *        config/security/REPORT_POLICY.php, for tests.
     */
    public function __construct(
        ?ReportDisposition $dispositions = null,
        ?RemediationTracker $tracker = null,
        ?RedactionScanner $redaction = null,
        ?array $policy = null
    ) {
        $this->tracker = $tracker ?? new RemediationTracker();
        $this->dispositions = $dispositions ?? new ReportDisposition($this->tracker);
        $this->redaction = $redaction ?? new RedactionScanner();

        $loaded = $policy ?? self::defaultPolicy();

        $this->trendLookbackDays = self::positiveInt($loaded, 'trend_lookback_days');
        $this->trendPeriods = self::positiveInt($loaded, 'trend_periods');
        $this->maxRows = self::positiveInt($loaded, 'max_report_rows');
        $this->maxTitleChars = self::positiveInt($loaded, 'max_title_chars');
    }

    /**
     * EXECUTIVE report (BRD section 6 "Executive risk report").
     *
     * A business reader's view: how many items, in what state, how much is
     * overdue. It carries the full disposition tally INCLUDING the zeroes, so
     * "nothing is unverified" and "we did not check" cannot look the same.
     *
     * Deliberately omits evidence detail and reproduction steps — an executive
     * summary that quotes a payload is an executive summary that leaks one.
     *
     * @param list<Finding>        $findings
     * @param list<Remediation>    $remediations
     * @param list<Retest>         $retests
     * @param list<RiskAcceptance> $acceptances
     */
    public function executive(
        int $tenantId,
        string $title,
        array $findings,
        array $remediations,
        array $retests,
        array $acceptances,
        DateTimeImmutable $now
    ): ReportData {
        $this->assertTenant($tenantId, $findings, $remediations, $retests, $acceptances);

        $classified = $this->classify($findings, $remediations, $retests, $acceptances, $now);
        $tally = $this->dispositions->tally(array_map(
            static fn (array $row): string => $row['disposition'],
            $classified
        ));

        $overdue = $this->tracker->overdue($remediations, $now);

        $sections = [];
        foreach ($tally as $disposition => $count) {
            $sections[] = [
                'disposition' => ReportDisposition::label($disposition),
                'items' => $count,
            ];
        }

        $metrics = [
            'total_findings' => count($findings),
            'overdue_remediations' => count($overdue),
            'active_risk_acceptances' => count($this->activeAcceptances($acceptances, $now)),
            'acceptances_needing_review' => count(
                $this->tracker->acceptancesNeedingReview($acceptances, $now)
            ),
        ];

        foreach ($tally as $disposition => $count) {
            $metrics[$disposition] = $count;
        }

        return $this->build(self::KIND_EXECUTIVE, $title, $metrics, $sections, $now);
    }

    /**
     * TECHNICAL report (BRD section 6 "Technical findings with evidence and
     * remediation").
     *
     * One row per finding with the facts an engineer needs to act: severity,
     * confidence, category, disposition, SLA, and the remediation guidance
     * already stored on the finding. Every value comes from
     * Finding::toReportArray() — the projection that exists precisely so a
     * report never reaches into a live object graph.
     *
     * @param list<Finding>        $findings
     * @param list<Remediation>    $remediations
     * @param list<Retest>         $retests
     * @param list<RiskAcceptance> $acceptances
     */
    public function technical(
        int $tenantId,
        string $title,
        array $findings,
        array $remediations,
        array $retests,
        array $acceptances,
        DateTimeImmutable $now
    ): ReportData {
        $this->assertTenant($tenantId, $findings, $remediations, $retests, $acceptances);

        $classified = $this->classify($findings, $remediations, $retests, $acceptances, $now);

        $sections = [];
        foreach ($classified as $row) {
            $finding = $row['finding']->toReportArray();

            $sections[] = [
                'finding_id' => $finding['id'],
                'title' => $finding['title'],
                'category' => $finding['category'],
                'severity' => $finding['severity'],
                'confidence' => $finding['confidence'],
                'disposition' => ReportDisposition::label($row['disposition']),
                'occurrences' => $finding['occurrence_count'],
                'sla_due_at' => $finding['sla_due_at'] ?? 'n/a',
                'remediation' => $finding['remediation'] ?? 'not recorded',
            ];
        }

        // Most severe first: a technical report read top-down should surface
        // the thing that matters most, not the lowest row id.
        usort($sections, function (array $a, array $b): int {
            $bySeverity = $this->severityRank((string) $b['severity'])
                <=> $this->severityRank((string) $a['severity']);

            return $bySeverity !== 0 ? $bySeverity : ((int) $a['finding_id'] <=> (int) $b['finding_id']);
        });

        return $this->build(
            self::KIND_TECHNICAL,
            $title,
            ['findings' => count($findings)],
            $sections,
            $now
        );
    }

    /**
     * COMPLIANCE MAPPING report (BRD section 6 "Standards mapping").
     *
     * Groups findings by the standards references already stored on them
     * (Finding::standardsMapping(), e.g. an ASVS or API Top 10 identifier), so
     * a client can see coverage against the agreed profile — BRD section 7's
     * "coverage against agreed ASVS/API/AI security profile" measure.
     *
     * The mapping is REPORTED, never invented: this class does not decide that
     * a finding maps to a control. If a finding carries no mapping it appears
     * under an explicit "unmapped" row rather than being dropped, because a
     * silently omitted finding is how a coverage report overstates coverage.
     *
     * @param list<Finding>        $findings
     * @param list<Remediation>    $remediations
     * @param list<Retest>         $retests
     * @param list<RiskAcceptance> $acceptances
     */
    public function complianceMapping(
        int $tenantId,
        string $title,
        array $findings,
        array $remediations,
        array $retests,
        array $acceptances,
        DateTimeImmutable $now
    ): ReportData {
        $this->assertTenant($tenantId, $findings, $remediations, $retests, $acceptances);

        $classified = $this->classify($findings, $remediations, $retests, $acceptances, $now);

        /** @var array<string, array{items: int, open: int}> $byControl */
        $byControl = [];

        foreach ($classified as $row) {
            $projection = $row['finding']->toReportArray();
            $controls = $projection['standards_mapping'];

            if ($controls === []) {
                $controls = ['unmapped'];
            }

            $settled = in_array(
                $row['disposition'],
                [ReportDisposition::REMEDIATED, ReportDisposition::ACCEPTED],
                true
            );

            foreach ($controls as $control) {
                $key = (string) $control;
                if (!array_key_exists($key, $byControl)) {
                    $byControl[$key] = ['items' => 0, 'open' => 0];
                }

                $byControl[$key]['items']++;
                if (!$settled) {
                    $byControl[$key]['open']++;
                }
            }
        }

        ksort($byControl);

        $sections = [];
        foreach ($byControl as $control => $counts) {
            $sections[] = [
                'control' => $control,
                'items' => $counts['items'],
                'outstanding' => $counts['open'],
            ];
        }

        return $this->build(
            self::KIND_COMPLIANCE,
            $title,
            ['controls_referenced' => count($byControl), 'findings' => count($findings)],
            $sections,
            $now
        );
    }

    /**
     * TREND AND POSTURE report (BRD section 6 "Trend and posture report for
     * recurring service").
     *
     * Buckets findings into consecutive lookback windows by when they were
     * FIRST seen, so a client on a recurring engagement can see whether the
     * programme's direction held. The window length and the number of periods
     * come from config/security/REPORT_POLICY.php — a trend over an
     * undeclared window is not a measurement (NIST SP 800-137: continuous
     * monitoring is defined against a stated frequency).
     *
     * Windows are counted BACK from the report moment, newest first, and the
     * period boundaries are stated in the output so two reports run a week
     * apart are comparable rather than merely similar.
     *
     * @param list<Finding>        $findings
     * @param list<Remediation>    $remediations
     * @param list<Retest>         $retests
     * @param list<RiskAcceptance> $acceptances
     */
    public function trend(
        int $tenantId,
        string $title,
        array $findings,
        array $remediations,
        array $retests,
        array $acceptances,
        DateTimeImmutable $now
    ): ReportData {
        $this->assertTenant($tenantId, $findings, $remediations, $retests, $acceptances);

        $classified = $this->classify($findings, $remediations, $retests, $acceptances, $now);

        $sections = [];
        $windowEnd = $now;

        for ($period = 0; $period < $this->trendPeriods; $period++) {
            $windowStart = $windowEnd->sub(new DateInterval('P' . $this->trendLookbackDays . 'D'));

            $opened = 0;
            $settled = 0;

            foreach ($classified as $row) {
                $firstSeen = $row['finding']->firstSeenAt();

                if ($firstSeen <= $windowStart || $firstSeen > $windowEnd) {
                    continue;
                }

                $opened++;

                if (
                    in_array(
                        $row['disposition'],
                        [ReportDisposition::REMEDIATED, ReportDisposition::ACCEPTED],
                        true
                    )
                ) {
                    $settled++;
                }
            }

            $sections[] = [
                'period_start' => $windowStart->format(self::TIMESTAMP_FORMAT),
                'period_end' => $windowEnd->format(self::TIMESTAMP_FORMAT),
                'findings_first_seen' => $opened,
                'settled' => $settled,
                'outstanding' => $opened - $settled,
            ];

            $windowEnd = $windowStart;
        }

        return $this->build(
            self::KIND_TREND,
            $title,
            [
                'lookback_days' => $this->trendLookbackDays,
                'periods' => $this->trendPeriods,
                'findings_in_scope' => count($findings),
            ],
            $sections,
            $now
        );
    }

    /**
     * ACCEPTANCE report — the exception / risk-acceptance register (BRD
     * section 6, SBR-5.3).
     *
     * SBR-5.3 requires an acceptance to name approver, rationale, compensating
     * control, review date and expiry, so the register shows all five: a
     * waiver whose justification is not visible is not reviewable.
     *
     * WHETHER AN ACCEPTANCE IS LIVE IS COMPUTED FROM THE CLOCK, never read
     * from a stored flag (RiskAcceptance::isActiveAt) — an expired waiver that
     * still reads "accepted" because a cron job did not run is exactly the
     * misreport this column exists to prevent. Expired and revoked entries
     * stay in the register, labelled, because a register that forgets its
     * lapsed waivers cannot evidence the decision that was made.
     *
     * @param list<RiskAcceptance> $acceptances
     */
    public function acceptanceRegister(
        int $tenantId,
        string $title,
        array $acceptances,
        DateTimeImmutable $now
    ): ReportData {
        $this->assertTenant($tenantId, [], [], [], $acceptances);

        $sorted = $acceptances;
        usort(
            $sorted,
            static fn (RiskAcceptance $a, RiskAcceptance $b): int => $a->expiresAt() <=> $b->expiresAt()
        );

        $sections = [];
        $active = 0;

        foreach ($sorted as $acceptance) {
            $projection = $acceptance->toReportArray();
            $isActive = $acceptance->isActiveAt($now);

            if ($isActive) {
                $active++;
            }

            $sections[] = [
                'finding_id' => $projection['finding_id'],
                'state' => $this->acceptanceState($acceptance, $now),
                'approver' => $projection['approver'],
                'rationale' => $projection['rationale'],
                'compensating_control' => $projection['compensating_control'],
                'review_at' => $projection['review_at'],
                'expires_at' => $projection['expires_at'],
            ];
        }

        return $this->build(
            self::KIND_ACCEPTANCE,
            $title,
            [
                'acceptances' => count($acceptances),
                'active' => $active,
                'needing_review' => count($this->tracker->acceptancesNeedingReview($acceptances, $now)),
            ],
            $sections,
            $now
        );
    }

    /**
     * RETEST report (BRD section 6 "Retest report", SFR-RETEST-001).
     *
     * One row per retest, plus the thing the report exists to make visible:
     * whether the retest actually CLOSED anything. A pass with no evidence
     * closes nothing (FRD section 7) and an inconclusive run closes nothing
     * (SFR-SCAN-003) — both appear here as themselves rather than as failures
     * or as successes.
     *
     * The "closes_finding" column is read from Retest::closesFinding(), the
     * same accessor the tracker uses, so the report cannot be more optimistic
     * than the write path.
     *
     * @param list<Retest> $retests
     */
    public function retestReport(
        int $tenantId,
        string $title,
        array $retests,
        DateTimeImmutable $now
    ): ReportData {
        $this->assertTenant($tenantId, [], [], $retests, []);

        $sorted = $retests;
        usort($sorted, static function (Retest $a, Retest $b): int {
            $byTime = $b->performedAt() <=> $a->performedAt();

            return $byTime !== 0 ? $byTime : $b->id() <=> $a->id();
        });

        $passed = 0;
        $closing = 0;

        $sections = [];
        foreach ($sorted as $retest) {
            $projection = $retest->toReportArray();

            if ($retest->result() === Retest::RESULT_PASS) {
                $passed++;
            }
            if ($retest->closesFinding()) {
                $closing++;
            }

            $sections[] = [
                'finding_id' => $projection['finding_id'],
                'remediation_id' => $projection['remediation_id'],
                'result' => $projection['result'],
                'has_evidence' => $retest->hasEvidence() ? 'yes' : 'no',
                'closes_finding' => $retest->closesFinding() ? 'yes' : 'no',
                'performed_by' => $projection['performed_by'],
                'performed_at' => $projection['performed_at'],
                // The tester's remark. Free text written by a human, so it is
                // both the most useful column in a retest report and the one
                // most able to carry a pasted token — which is precisely what
                // the redaction gate in build() inspects.
                'note' => $projection['note'] ?? '',
            ];
        }

        return $this->build(
            self::KIND_RETEST,
            $title,
            [
                'retests' => count($retests),
                'passed' => $passed,
                'closing' => $closing,
                // A pass that closes nothing is the interesting number: it is
                // the gap between "we ran it again" and "it is fixed".
                'passed_without_closure' => $passed - $closing,
            ],
            $sections,
            $now
        );
    }

    /**
     * Classifies every finding once, so all six reports agree.
     *
     * @param list<Finding>        $findings
     * @param list<Remediation>    $remediations
     * @param list<Retest>         $retests
     * @param list<RiskAcceptance> $acceptances
     *
     * @return list<array{finding: Finding, disposition: string}>
     */
    private function classify(
        array $findings,
        array $remediations,
        array $retests,
        array $acceptances,
        DateTimeImmutable $now
    ): array {
        $out = [];

        foreach ($findings as $finding) {
            $remediation = $this->remediationFor($finding->id(), $remediations);

            $out[] = [
                'finding' => $finding,
                'disposition' => $this->dispositions->forFinding(
                    $finding,
                    $remediation,
                    $remediation === null
                        ? []
                        : $this->retestsFor($remediation->id(), $retests),
                    $this->acceptancesFor($finding->id(), $acceptances),
                    $now
                ),
            ];
        }

        return $out;
    }

    /**
     * @param list<Remediation> $remediations
     */
    private function remediationFor(int $findingId, array $remediations): ?Remediation
    {
        foreach ($remediations as $remediation) {
            if ($remediation->findingId() === $findingId) {
                return $remediation;
            }
        }

        return null;
    }

    /**
     * @param list<Retest> $retests
     *
     * @return list<Retest>
     */
    private function retestsFor(int $remediationId, array $retests): array
    {
        $out = [];
        foreach ($retests as $retest) {
            if ($retest->remediationId() === $remediationId) {
                $out[] = $retest;
            }
        }

        return $out;
    }

    /**
     * @param list<RiskAcceptance> $acceptances
     *
     * @return list<RiskAcceptance>
     */
    private function acceptancesFor(int $findingId, array $acceptances): array
    {
        $out = [];
        foreach ($acceptances as $acceptance) {
            if ($acceptance->findingId() === $findingId) {
                $out[] = $acceptance;
            }
        }

        return $out;
    }

    /**
     * @param list<RiskAcceptance> $acceptances
     *
     * @return list<RiskAcceptance>
     */
    private function activeAcceptances(array $acceptances, DateTimeImmutable $now): array
    {
        $out = [];
        foreach ($acceptances as $acceptance) {
            if ($acceptance->isActiveAt($now)) {
                $out[] = $acceptance;
            }
        }

        return $out;
    }

    /**
     * The register's state column — derived, never stored.
     */
    private function acceptanceState(RiskAcceptance $acceptance, DateTimeImmutable $now): string
    {
        if ($acceptance->status() === RiskAcceptance::STATUS_REVOKED) {
            return 'revoked';
        }

        if ($acceptance->hasExpiredAt($now)) {
            return 'expired';
        }

        if ($acceptance->isDueForReviewAt($now)) {
            return 'active (review due)';
        }

        return 'active';
    }

    /**
     * Severity ordering for presentation only. Reuses Finding::SEVERITIES so a
     * new severity cannot be silently unranked.
     */
    private function severityRank(string $severity): int
    {
        $rank = array_search($severity, Finding::SEVERITIES, true);

        return $rank === false ? -1 : $rank;
    }

    /**
     * Applies the two gates and produces the value object.
     *
     * @param array<string, mixed>       $metrics
     * @param list<array<string, mixed>> $sections
     */
    private function build(
        string $kind,
        string $title,
        array $metrics,
        array $sections,
        DateTimeImmutable $now
    ): ReportData {
        if (!in_array($kind, self::KINDS, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown security report kind "%s". FRD section 2 names six: %s (allowlist, '
                . 'AC-002).',
                $kind,
                implode(', ', self::KINDS)
            ));
        }

        if (count($sections) > $this->maxRows) {
            // Refuse rather than truncate: a partial register that reads as
            // complete is the failure mode (config/security/REPORT_POLICY.php).
            throw new RuntimeException(sprintf(
                'This report would carry %d rows, beyond the %d-row ceiling in '
                . 'config/security/REPORT_POLICY.php. Narrow the reporting window rather than '
                . 'emitting a partial register that reads as complete.',
                count($sections),
                $this->maxRows
            ));
        }

        $safeTitle = mb_substr(trim($title), 0, $this->maxTitleChars);

        $this->assertRedacted($safeTitle, $metrics, $sections);

        return new ReportData(
            $kind,
            $safeTitle,
            $metrics,
            $sections,
            $now->format(DateTimeImmutable::ATOM)
        );
    }

    /**
     * THE REPORT-REDACTION GATE (FRD section 7, SFR-AUTH-003).
     *
     * Scans the assembled title, metrics and body with the SAME
     * RedactionScanner the evidence layer uses, and refuses the report if a
     * secret or a session token reaches it.
     *
     * WHY ONLY THOSE TWO KINDS ARE FATAL. The acceptance test names exactly
     * "secrets and session tokens", and SFR-AUTH-003 names credentials. The
     * scanner's other two kinds are different questions: personal data is
     * legitimately present in a security report (an owner, an approver and a
     * verifier are named people, and SBR-5.3 REQUIRES the approver's name), and
     * a response-body key is an evidence-layer concern that never reaches this
     * shape. Making those fatal would make every lawful report unemittable,
     * which is how a safety control gets switched off in production.
     *
     * @param array<string, mixed>       $metrics
     * @param list<array<string, mixed>> $sections
     *
     * @throws ReportRedactionRequired When a secret or session token is found.
     */
    private function assertRedacted(string $title, array $metrics, array $sections): void
    {
        $this->assertCellClean('title', $title);

        foreach ($metrics as $key => $value) {
            $this->assertCellClean('metric:' . (string) $key, $value);
        }

        foreach ($sections as $index => $row) {
            foreach ($row as $column => $value) {
                $this->assertCellClean(sprintf('row[%d].%s', $index, (string) $column), $value);
            }
        }
    }

    /**
     * @throws ReportRedactionRequired
     */
    private function assertCellClean(string $field, mixed $value): void
    {
        if (!is_string($value) || $value === '') {
            return;
        }

        // Scan under BOTH a neutral key and the field's own name: the scanner
        // reads key allowlists as well as value patterns, so a value sitting
        // under a field literally called "token" must be caught by the key
        // rule too.
        $column = $this->columnName($field);
        $kinds = $this->redaction->scan([$column => $value]);

        $fatal = array_values(array_intersect(
            $kinds,
            [RedactionScanner::KIND_SECRET, RedactionScanner::KIND_SESSION_TOKEN]
        ));

        if ($fatal === []) {
            return;
        }

        throw new ReportRedactionRequired(
            $fatal,
            $field,
            sprintf(
                'Report refused: field "%s" carries %s. Secrets and session tokens must be '
                . 'absent from report output (FRD section 7 "Report redaction", SFR-AUTH-003). '
                . 'The value reaching a report means an upstream redaction control did not '
                . 'hold; fix that rather than scrubbing here.',
                $field,
                implode(' and ', $fatal)
            )
        );
    }

    /**
     * The bare column name a cell sits under, for the scanner's key rules.
     *
     * Only names in SCANNED_FIELDS are handed to the scanner as a meaningful
     * key; anything else is scanned by value alone under a neutral key, so an
     * integer column called "owner_id" is not treated as a person's name.
     */
    private function columnName(string $field): string
    {
        $bare = $field;

        $dot = strrpos($bare, '.');
        if ($dot !== false) {
            $bare = substr($bare, $dot + 1);
        }

        $colon = strrpos($bare, ':');
        if ($colon !== false) {
            $bare = substr($bare, $colon + 1);
        }

        return in_array($bare, self::SCANNED_FIELDS, true) ? $bare : 'report_cell';
    }

    /**
     * Every value object in the report must belong to the report's tenant
     * (FRD section 7 "Cross tenant"). See CrossTenantReportRefused.
     *
     * @param list<Finding>        $findings
     * @param list<Remediation>    $remediations
     * @param list<Retest>         $retests
     * @param list<RiskAcceptance> $acceptances
     *
     * @throws CrossTenantReportRefused
     */
    private function assertTenant(
        int $tenantId,
        array $findings,
        array $remediations,
        array $retests,
        array $acceptances
    ): void {
        if ($tenantId <= 0) {
            throw new InvalidArgumentException(
                'A report needs the tenant it is for; scope is not optional (AC-001).'
            );
        }

        foreach ($findings as $finding) {
            $this->assertSameTenant($tenantId, $finding->tenantId(), 'finding');
        }

        foreach ($remediations as $remediation) {
            $this->assertSameTenant($tenantId, $remediation->tenantId(), 'remediation');
        }

        foreach ($retests as $retest) {
            $this->assertSameTenant($tenantId, $retest->tenantId(), 'retest');
        }

        foreach ($acceptances as $acceptance) {
            $this->assertSameTenant($tenantId, $acceptance->tenantId(), 'risk acceptance');
        }
    }

    /**
     * @throws CrossTenantReportRefused
     */
    private function assertSameTenant(int $reportTenantId, int $rowTenantId, string $itemType): void
    {
        if ($rowTenantId === $reportTenantId) {
            return;
        }

        throw new CrossTenantReportRefused(
            $reportTenantId,
            $rowTenantId,
            $itemType,
            sprintf(
                'Report refused: a %s belonging to tenant %d was passed into a report for '
                . 'tenant %d. No finding, evidence or report access across tenant (FRD '
                . 'section 7 "Cross tenant", AC-001).',
                $itemType,
                $rowTenantId,
                $reportTenantId
            )
        );
    }

    public function trendLookbackDays(): int
    {
        return $this->trendLookbackDays;
    }

    public function trendPeriods(): int
    {
        return $this->trendPeriods;
    }

    public function maxReportRows(): int
    {
        return $this->maxRows;
    }

    /**
     * The ratifiable policy from config/security/REPORT_POLICY.php.
     *
     * @return array<string, int>
     */
    private static function defaultPolicy(): array
    {
        $path = dirname(__DIR__, 2) . '/config/security/REPORT_POLICY.php';

        if (!is_file($path)) {
            throw new RuntimeException(sprintf(
                'The report policy file is missing at "%s"; report windows are configured, '
                . 'not hardcoded.',
                $path
            ));
        }

        /** @var mixed $loaded */
        $loaded = require $path;

        if (!is_array($loaded)) {
            throw new RuntimeException('The report policy file must return an array.');
        }

        $policy = [];
        foreach ($loaded as $key => $value) {
            if (is_string($key) && is_int($value)) {
                $policy[$key] = $value;
            }
        }

        return $policy;
    }

    /**
     * @param array<string, int> $policy
     */
    private static function positiveInt(array $policy, string $key): int
    {
        if (!array_key_exists($key, $policy)) {
            // Fail closed: a missing window would otherwise become an
            // unbounded or zero-length one depending on the reader.
            throw new InvalidArgumentException(sprintf(
                'The report policy does not define "%s".',
                $key
            ));
        }

        $value = $policy[$key];
        if ($value <= 0) {
            throw new InvalidArgumentException(sprintf(
                'The report policy value "%s" must be positive.',
                $key
            ));
        }

        return $value;
    }
}
