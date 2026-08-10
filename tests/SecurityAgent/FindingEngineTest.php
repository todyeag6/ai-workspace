<?php

declare(strict_types=1);

namespace App\Tests\SecurityAgent;

use App\Audit\AuditLogger;
use App\SecurityAgent\AuthorizationRepository;
use App\SecurityAgent\Finding;
use App\SecurityAgent\FindingEngine;
use App\SecurityAgent\FindingRepository;
use App\SecurityAgent\HumanDecisionRequired;
use App\SecurityAgent\ScanProfileRepository;
use App\SecurityAgent\ScanRepository;
use App\Tests\TestCase;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PDO;
use RuntimeException;

/**
 * P3-T5 - Finding Engine (the component after the Evidence Processor in the
 * FRD's order: Evidence Processor -> Finding Engine -> Reporting).
 *
 * Each test maps to a baseline requirement:
 *
 *  - SFR-FIND-001: findings shall have unique fingerprint, title, category,
 *    severity, confidence, affected assets, evidence, remediation, standards
 *    mapping, owner, status, SLA and history.
 *  - SFR-FIND-002: repeated evidence shall update occurrence history WITHOUT
 *    destroying previous state.
 *  - SFR-AI-001: AI may summarize and suggest severity/remediation but shall
 *    not alter confirmed status, close findings, or authorize risk acceptance
 *    without human decision.
 *  - SFR-AUD-001: finding, severity and assignment changes shall be audited.
 *  - SBR-5.1 / 5.2: critical and high findings generate configured deadlines;
 *    a false-positive disposition requires reason and reviewer.
 *  - AC-001: no finding/evidence access across tenant (FRD section 7
 *    "Cross tenant" acceptance test).
 *  - FRD section 7 "Deduplication": repeated finding updates occurrence
 *    without losing history.
 *
 * © AI WebScapes 2026
 */
final class FindingEngineTest extends TestCase
{
    // ---------------------------------------------------------------
    // SFR-FIND-001 - a finding carries every required field
    // ---------------------------------------------------------------

    public function test_finding_captures_every_required_field(): void
    {
        $this->seedTenant(1);
        $scanId = $this->scheduleScan(1);

        $id = $this->findings(1)->record(
            title: 'TLS 1.0 accepted on public endpoint',
            category: Finding::CATEGORY_TRANSPORT_EXPOSURE,
            canonicalAsset: 'app.acme.test',
            signature: ['protocol' => 'TLSv1.0', 'port' => 443],
            baseSeverity: Finding::SEVERITY_HIGH,
            confidence: Finding::CONFIDENCE_HIGH,
            scanId: $scanId,
            observedAt: $this->at('2026-03-01 09:00:00')
        );

        $finding = $this->findings(1)->requireById($id);

        // Everything SFR-FIND-001 enumerates is present and readable.
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $finding->fingerprint());
        self::assertSame('TLS 1.0 accepted on public endpoint', $finding->title());
        self::assertSame(Finding::CATEGORY_TRANSPORT_EXPOSURE, $finding->category());
        self::assertSame(Finding::SEVERITY_HIGH, $finding->severity());
        self::assertSame(Finding::CONFIDENCE_HIGH, $finding->confidence());
        self::assertSame([], $finding->affectedAssets());
        self::assertNull($finding->remediation());
        self::assertNotEmpty($finding->standardsMapping(), 'A finding must map to standards.');
        self::assertSame('', $finding->owner(), 'Unassigned is a visible state, not a null.');
        self::assertSame(Finding::STATUS_OPEN, $finding->status());
        self::assertNotNull($finding->slaDueAt(), 'A high finding carries a remediation deadline.');
        self::assertSame('2026-03-01 09:00:00', $this->stamp($finding->firstSeenAt()));
        self::assertSame('2026-03-01 09:00:00', $this->stamp($finding->lastSeenAt()));
        self::assertSame(1, $finding->occurrenceCount());

        // ... and the report projection exposes all of them in one place.
        $report = $finding->toReportArray();
        foreach (
            [
                'fingerprint', 'title', 'category', 'severity', 'confidence',
                'affected_assets', 'remediation', 'standards_mapping', 'owner',
                'status', 'sla_due_at', 'first_seen_at', 'last_seen_at',
                'occurrence_count',
            ] as $field
        ) {
            self::assertArrayHasKey($field, $report, sprintf('SFR-FIND-001 requires %s.', $field));
        }
    }

    public function test_fingerprint_is_stable_across_runs_and_scanner_versions(): void
    {
        $engine = new FindingEngine();

        $a = $engine->fingerprint(
            Finding::CATEGORY_HTTP_CONFIGURATION,
            'app.acme.test',
            ['header' => 'Strict-Transport-Security', 'present' => false]
        );
        // Same issue, keys in a different order - must fingerprint identically.
        $b = $engine->fingerprint(
            Finding::CATEGORY_HTTP_CONFIGURATION,
            'app.acme.test',
            ['present' => false, 'header' => 'Strict-Transport-Security']
        );
        // Same issue, host spelled with different case - still one finding.
        $c = $engine->fingerprint(
            Finding::CATEGORY_HTTP_CONFIGURATION,
            'APP.acme.TEST',
            ['header' => 'Strict-Transport-Security', 'present' => false]
        );

        self::assertSame($a, $b, 'Key order must not fork the finding (SFR-FIND-002).');
        self::assertSame($a, $c, 'Asset case must not fork the finding.');

        // A different asset, or a different category, IS a different finding.
        self::assertNotSame($a, $engine->fingerprint(
            Finding::CATEGORY_HTTP_CONFIGURATION,
            'other.acme.test',
            ['header' => 'Strict-Transport-Security', 'present' => false]
        ));
        self::assertNotSame($a, $engine->fingerprint(
            Finding::CATEGORY_CONTENT_EXPOSURE,
            'app.acme.test',
            ['header' => 'Strict-Transport-Security', 'present' => false]
        ));
    }

    public function test_unknown_category_and_severity_are_refused_not_guessed(): void
    {
        $engine = new FindingEngine();

        // AC-002: allowlist, not denylist. An unknown value is refused rather
        // than stored and guessed at downstream.
        $this->expectException(InvalidArgumentException::class);
        $engine->fingerprint('made-up-category', 'app.acme.test', []);
    }

    public function test_standards_mapping_comes_from_the_category(): void
    {
        $engine = new FindingEngine();

        $ai = $engine->mapStandards(Finding::CATEGORY_AI_SECURITY);
        self::assertContains('OWASP GenAI:LLM01-Prompt-Injection', $ai);

        $injection = $engine->mapStandards(Finding::CATEGORY_INPUT_HANDLING);
        self::assertContains('OWASP Top 10:2025:A03-Injection', $injection);

        // Every category maps to at least one authoritative standard.
        foreach (Finding::CATEGORIES as $category) {
            self::assertNotEmpty(
                $engine->mapStandards($category),
                sprintf('Category %s must map to a standard (SFR-FIND-001).', $category)
            );
        }
    }

    // ---------------------------------------------------------------
    // SBR-5.1 - configured remediation deadlines
    // ---------------------------------------------------------------

    public function test_sla_is_derived_from_severity_and_first_sighting(): void
    {
        // The policy is injected, mirroring config/security/FINDING_SLA.php -
        // the numbers are configured (SBR-5.1), not hardcoded in the engine.
        $engine = new FindingEngine([
            Finding::SEVERITY_CRITICAL => 24,
            Finding::SEVERITY_HIGH => 72,
            Finding::SEVERITY_MEDIUM => 336,
            Finding::SEVERITY_LOW => 2160,
            Finding::SEVERITY_INFORMATIONAL => null,
        ]);

        $first = $this->at('2026-03-01 09:00:00');

        self::assertSame(
            '2026-03-02 09:00:00',
            $this->stamp($engine->slaDueAt(Finding::SEVERITY_CRITICAL, $first))
        );
        self::assertSame(
            '2026-03-04 09:00:00',
            $this->stamp($engine->slaDueAt(Finding::SEVERITY_HIGH, $first))
        );
        // Informational carries no remediation clock, so nothing is overdue.
        self::assertNull($engine->slaDueAt(Finding::SEVERITY_INFORMATIONAL, $first));

        // SBR-5.1 names critical and high as the alerting severities.
        self::assertTrue($engine->requiresAlert(Finding::SEVERITY_CRITICAL));
        self::assertTrue($engine->requiresAlert(Finding::SEVERITY_HIGH));
        self::assertFalse($engine->requiresAlert(Finding::SEVERITY_MEDIUM));
    }

    public function test_sla_policy_missing_a_severity_is_refused(): void
    {
        // Fail closed: an incomplete policy would silently leave some findings
        // with no deadline, and "no deadline" must be a stated decision.
        $this->expectException(InvalidArgumentException::class);
        new FindingEngine([Finding::SEVERITY_CRITICAL => 24]);
    }

    public function test_shipped_sla_policy_file_covers_every_severity(): void
    {
        // The real config/security/FINDING_SLA.php must satisfy the same
        // completeness contract - otherwise the default constructor throws in
        // production and nowhere else.
        $engine = new FindingEngine();

        foreach (Finding::SEVERITIES as $severity) {
            $due = $engine->slaDueAt($severity, $this->at('2026-03-01 09:00:00'));
            if ($severity === Finding::SEVERITY_INFORMATIONAL) {
                self::assertNull($due);
                continue;
            }

            self::assertNotNull($due, sprintf('Severity %s must carry a deadline.', $severity));
        }
    }

    // ---------------------------------------------------------------
    // SFR-FIND-002 / FRD section 7 "Deduplication"
    // ---------------------------------------------------------------

    public function test_repeated_evidence_appends_occurrence_without_destroying_state(): void
    {
        $this->seedTenant(1);
        $repo = $this->findings(1);
        $scanA = $this->scheduleScan(1);
        $scanB = $this->scheduleScan(1);

        $args = [
            'title' => 'Directory listing enabled',
            'category' => Finding::CATEGORY_CONTENT_EXPOSURE,
            'canonicalAsset' => 'app.acme.test',
            'signature' => ['path' => '/backups/'],
            'baseSeverity' => Finding::SEVERITY_MEDIUM,
            'confidence' => Finding::CONFIDENCE_HIGH,
        ];

        $id = $repo->record(...[...$args, 'scanId' => $scanA, 'observedAt' => $this->at('2026-03-01 09:00:00')]);

        // A human then reviews it: confirms it and assigns an owner.
        $repo->transitionStatus($id, Finding::STATUS_CONFIRMED, 'alice@aiwebscapes.test');
        $repo->assignOwner($id, 'bob@acme.test');
        $repo->setRemediation($id, 'Disable autoindex on the backups location.');

        // A LATER scan makes the SAME observation.
        $again = $repo->record(...[...$args, 'scanId' => $scanB, 'observedAt' => $this->at('2026-03-08 09:00:00')]);

        // It is the SAME finding - no duplicate row (SFR-FIND-002).
        self::assertSame($id, $again, 'A repeat sighting must not create a second finding.');

        $finding = $repo->requireById($id);

        // History GREW ...
        self::assertSame(2, $finding->occurrenceCount());
        self::assertSame('2026-03-08 09:00:00', $this->stamp($finding->lastSeenAt()));
        // ... and the original first sighting was NOT moved.
        self::assertSame('2026-03-01 09:00:00', $this->stamp($finding->firstSeenAt()));

        // ... while NONE of the human's decisions were destroyed.
        self::assertSame(Finding::STATUS_CONFIRMED, $finding->status());
        self::assertSame('alice@aiwebscapes.test', $finding->confirmedBy());
        self::assertSame('bob@acme.test', $finding->owner());
        self::assertSame('Disable autoindex on the backups location.', $finding->remediation());

        // Both sightings survive as separate, ordered occurrence rows.
        $history = $repo->occurrencesFor($id);
        self::assertCount(2, $history);
        self::assertSame('2026-03-01 09:00:00', $this->stamp($history[0]->observedAt()));
        self::assertSame('2026-03-08 09:00:00', $this->stamp($history[1]->observedAt()));
        self::assertSame($scanA, $history[0]->scanId());
        self::assertSame($scanB, $history[1]->scanId());

        // And the occurrence records the disposition AS IT WAS at the time:
        // open on first sight, confirmed by the time of the second.
        self::assertSame(Finding::STATUS_OPEN, $history[0]->statusAtObservation());
        self::assertSame(Finding::STATUS_CONFIRMED, $history[1]->statusAtObservation());
    }

    public function test_re_observing_a_risk_accepted_finding_does_not_reopen_it(): void
    {
        $this->seedTenant(1);
        $repo = $this->findings(1);
        $scanId = $this->scheduleScan(1);

        $args = [
            'title' => 'Legacy cipher suite offered',
            'category' => Finding::CATEGORY_TRANSPORT_EXPOSURE,
            'canonicalAsset' => 'legacy.acme.test',
            'signature' => ['cipher' => 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'],
            'baseSeverity' => Finding::SEVERITY_LOW,
            'confidence' => Finding::CONFIDENCE_MEDIUM,
            'scanId' => $scanId,
        ];

        $id = $repo->record(...$args);
        // SBR-5.3: a human accepts the risk.
        $repo->transitionStatus($id, Finding::STATUS_RISK_ACCEPTED, 'ciso@acme.test', reason: 'Vendor EOL Q4');

        // The next scan sees it again. It must NOT be silently reopened - that
        // would erase a signed-off business decision (SFR-FIND-002).
        $repo->record(...$args);

        $finding = $repo->requireById($id);
        self::assertSame(Finding::STATUS_RISK_ACCEPTED, $finding->status());
        self::assertSame(2, $finding->occurrenceCount());
    }

    public function test_a_new_asset_widens_the_finding_rather_than_forking_it(): void
    {
        $this->seedTenant(1);
        $repo = $this->findings(1);
        $scanId = $this->scheduleScan(1);
        $assetA = $this->seedAsset(1, 'a.acme.test');
        $assetB = $this->seedAsset(1, 'b.acme.test');

        $args = [
            'title' => 'Missing Content-Security-Policy',
            'category' => Finding::CATEGORY_HTTP_CONFIGURATION,
            'canonicalAsset' => 'acme.test',
            'signature' => ['header' => 'Content-Security-Policy'],
            'baseSeverity' => Finding::SEVERITY_MEDIUM,
            'confidence' => Finding::CONFIDENCE_HIGH,
            'scanId' => $scanId,
        ];

        $id = $repo->record(...[...$args, 'assetId' => $assetA]);
        $repo->record(...[...$args, 'assetId' => $assetB]);

        $finding = $repo->requireById($id);
        self::assertSame([$assetA, $assetB], $finding->affectedAssets());
        self::assertSame(2, $finding->occurrenceCount());
    }

    // ---------------------------------------------------------------
    // SFR-AI-001 - AI suggests, humans decide
    // ---------------------------------------------------------------

    public function test_ai_suggestion_never_alters_the_authoritative_decision(): void
    {
        $this->seedTenant(1);
        $repo = $this->findings(1);
        $scanId = $this->scheduleScan(1);

        $id = $repo->record(
            title: 'Verbose error page discloses stack trace',
            category: Finding::CATEGORY_HTTP_CONFIGURATION,
            canonicalAsset: 'app.acme.test',
            signature: ['status' => 500],
            baseSeverity: Finding::SEVERITY_LOW,
            confidence: Finding::CONFIDENCE_MEDIUM,
            scanId: $scanId
        );
        $repo->transitionStatus($id, Finding::STATUS_CONFIRMED, 'alice@aiwebscapes.test');

        $before = $repo->requireById($id);

        // The AI weighs in: it thinks this is critical and proposes a fix.
        $repo->attachAiSuggestion(
            $id,
            Finding::SEVERITY_CRITICAL,
            'Disable detailed errors in production.',
            'Stack trace exposed on 500 responses.'
        );

        $after = $repo->requireById($id);

        // The SUGGESTION landed ...
        self::assertSame(Finding::SEVERITY_CRITICAL, $after->aiSuggestedSeverity());
        self::assertSame('Disable detailed errors in production.', $after->aiSuggestedRemediation());
        self::assertSame('Stack trace exposed on 500 responses.', $after->aiSummary());

        // ... and NOTHING authoritative moved (SFR-AI-001, BRD section 5).
        self::assertSame($before->severity(), $after->severity(), 'AI must not alter severity.');
        self::assertSame($before->status(), $after->status(), 'AI must not alter confirmed status.');
        self::assertSame($before->remediation(), $after->remediation(), 'AI must not alter remediation.');
        self::assertSame($before->confidence(), $after->confidence());
        self::assertSame($before->owner(), $after->owner());
    }

    public function test_closing_a_finding_without_a_human_is_refused(): void
    {
        $this->seedTenant(1);
        $repo = $this->findings(1);
        $scanId = $this->scheduleScan(1);

        $id = $repo->record(
            title: 'Open redirect',
            category: Finding::CATEGORY_INPUT_HANDLING,
            canonicalAsset: 'app.acme.test',
            signature: ['param' => 'next'],
            baseSeverity: Finding::SEVERITY_MEDIUM,
            confidence: Finding::CONFIDENCE_HIGH,
            scanId: $scanId
        );

        // Every status SFR-AI-001 reserves for a human must refuse an unnamed
        // decider - fail closed, and say which transition needed the human.
        foreach (Finding::HUMAN_ONLY_STATUSES as $status) {
            try {
                $repo->transitionStatus($id, $status, '');
                self::fail(sprintf('Expected HumanDecisionRequired for status "%s".', $status));
            } catch (HumanDecisionRequired $e) {
                self::assertSame($status, $e->attemptedStatus());
                self::assertStringContainsString('SFR-AI-001', $e->getMessage());
            }
        }

        // The finding is untouched: still open.
        self::assertSame(Finding::STATUS_OPEN, $repo->requireById($id)->status());
    }

    public function test_revising_severity_without_a_human_is_refused(): void
    {
        $this->seedTenant(1);
        $repo = $this->findings(1);
        $scanId = $this->scheduleScan(1);

        $id = $repo->record(
            title: 'Weak password policy',
            category: Finding::CATEGORY_AUTHENTICATION_SESSION,
            canonicalAsset: 'app.acme.test',
            signature: ['min_length' => 6],
            baseSeverity: Finding::SEVERITY_MEDIUM,
            confidence: Finding::CONFIDENCE_HIGH,
            scanId: $scanId,
            observedAt: $this->at('2026-03-01 09:00:00')
        );

        // BRD section 5: automated severity is ADVISORY until validated. The
        // validation is a human act, so an unnamed reviser is refused.
        try {
            $repo->reviseSeverity($id, Finding::SEVERITY_CRITICAL, '');
            self::fail('Expected HumanDecisionRequired.');
        } catch (HumanDecisionRequired $e) {
            self::assertStringContainsString('advisory', $e->getMessage());
        }

        // A named human CAN revise it, and the SLA is recomputed from the
        // FIRST sighting - not from now, which would grant a fresh clock.
        $repo->reviseSeverity($id, Finding::SEVERITY_CRITICAL, 'alice@aiwebscapes.test');
        $finding = $repo->requireById($id);
        self::assertSame(Finding::SEVERITY_CRITICAL, $finding->severity());
        self::assertSame('2026-03-02 09:00:00', $this->stamp($finding->slaDueAt()));
    }

    public function test_false_positive_requires_reason_and_reviewer(): void
    {
        $this->seedTenant(1);
        $repo = $this->findings(1);
        $scanId = $this->scheduleScan(1);

        $id = $repo->record(
            title: 'Suspected SQL injection',
            category: Finding::CATEGORY_INPUT_HANDLING,
            canonicalAsset: 'app.acme.test',
            signature: ['param' => 'id'],
            baseSeverity: Finding::SEVERITY_HIGH,
            confidence: Finding::CONFIDENCE_LOW,
            scanId: $scanId
        );

        // SBR-5.2: reviewer AND reason. A reviewer with no stated reason is
        // exactly the disposition that hides mistakes.
        $this->expectException(RuntimeException::class);
        $repo->transitionStatus($id, Finding::STATUS_FALSE_POSITIVE, 'alice@aiwebscapes.test');
    }

    public function test_low_confidence_evidence_derates_the_suggested_severity(): void
    {
        $engine = new FindingEngine();

        // BRD section 5 lists evidence confidence among the severity inputs.
        // An unvalidated observation should not raise a critical alarm alone.
        self::assertSame(
            Finding::SEVERITY_MEDIUM,
            $engine->score(Finding::SEVERITY_HIGH, Finding::CONFIDENCE_LOW)
        );
        // High confidence does NOT promote - the engine must not talk itself up.
        self::assertSame(
            Finding::SEVERITY_HIGH,
            $engine->score(Finding::SEVERITY_HIGH, Finding::CONFIDENCE_HIGH)
        );
        self::assertSame(
            Finding::SEVERITY_INFORMATIONAL,
            $engine->score(Finding::SEVERITY_INFORMATIONAL, Finding::CONFIDENCE_LOW)
        );
    }

    public function test_a_new_finding_is_born_open_and_never_confirmed(): void
    {
        $this->seedTenant(1);
        $scanId = $this->scheduleScan(1);

        $id = $this->findings(1)->record(
            title: 'Server header discloses version',
            category: Finding::CATEGORY_HTTP_CONFIGURATION,
            canonicalAsset: 'app.acme.test',
            signature: ['header' => 'Server'],
            baseSeverity: Finding::SEVERITY_LOW,
            confidence: Finding::CONFIDENCE_HIGH,
            scanId: $scanId
        );

        $finding = $this->findings(1)->requireById($id);

        // Nothing is validated by having been observed once (SFR-AI-001) - and
        // the machine's number is recorded AS a suggestion so its provenance
        // stays visible (BRD section 5).
        self::assertSame(Finding::STATUS_OPEN, $finding->status());
        self::assertFalse($finding->isConfirmed());
        self::assertNull($finding->confirmedBy());
        self::assertSame(Finding::SEVERITY_LOW, $finding->aiSuggestedSeverity());
    }

    // ---------------------------------------------------------------
    // SFR-AUD-001 - finding, severity and assignment changes are audited
    // ---------------------------------------------------------------

    public function test_human_decisions_are_audited(): void
    {
        $this->seedTenant(1);
        $repo = $this->findings(1);
        $scanId = $this->scheduleScan(1);

        $id = $repo->record(
            title: 'Missing rate limiting on login',
            category: Finding::CATEGORY_AUTHENTICATION_SESSION,
            canonicalAsset: 'app.acme.test',
            signature: ['endpoint' => '/login'],
            baseSeverity: Finding::SEVERITY_HIGH,
            confidence: Finding::CONFIDENCE_HIGH,
            scanId: $scanId
        );

        $repo->transitionStatus($id, Finding::STATUS_CONFIRMED, 'alice@aiwebscapes.test');
        $repo->reviseSeverity($id, Finding::SEVERITY_CRITICAL, 'alice@aiwebscapes.test');
        $repo->assignOwner($id, 'bob@acme.test');

        $actions = $this->auditActionsFor((string) $id);

        // SFR-AUD-001 names finding, severity and assignment changes.
        self::assertContains(FindingRepository::AUDIT_CONFIRM, $actions);
        self::assertContains(FindingRepository::AUDIT_SEVERITY, $actions);
        self::assertContains(FindingRepository::AUDIT_ASSIGN, $actions);
    }

    public function test_a_decision_cannot_be_made_unevidenced(): void
    {
        $this->seedTenant(1);
        $scanId = $this->scheduleScan(1);

        // Built WITHOUT an AuditLogger: a change nobody can evidence is not
        // one this repository will make (SFR-AUD-001, fail closed).
        $unaudited = new FindingRepository($this->pdo, 1);
        $id = $unaudited->record(
            title: 'Cookie missing Secure attribute',
            category: Finding::CATEGORY_AUTHENTICATION_SESSION,
            canonicalAsset: 'app.acme.test',
            signature: ['cookie' => 'session'],
            baseSeverity: Finding::SEVERITY_MEDIUM,
            confidence: Finding::CONFIDENCE_HIGH,
            scanId: $scanId
        );

        $this->expectException(RuntimeException::class);
        $unaudited->transitionStatus($id, Finding::STATUS_CONFIRMED, 'alice@aiwebscapes.test');
    }

    // ---------------------------------------------------------------
    // SBR-5.1 - overdue tracking
    // ---------------------------------------------------------------

    public function test_overdue_excludes_closed_findings(): void
    {
        $this->seedTenant(1);
        $repo = $this->findings(1);
        $scanId = $this->scheduleScan(1);

        $open = $repo->record(
            title: 'Unpatched dependency',
            category: Finding::CATEGORY_DEPENDENCIES,
            canonicalAsset: 'app.acme.test',
            signature: ['package' => 'left-pad', 'version' => '1.0.0'],
            baseSeverity: Finding::SEVERITY_CRITICAL,
            confidence: Finding::CONFIDENCE_HIGH,
            scanId: $scanId,
            observedAt: $this->at('2026-03-01 09:00:00')
        );
        $fixed = $repo->record(
            title: 'Unpatched dependency (other)',
            category: Finding::CATEGORY_DEPENDENCIES,
            canonicalAsset: 'other.acme.test',
            signature: ['package' => 'right-pad', 'version' => '1.0.0'],
            baseSeverity: Finding::SEVERITY_CRITICAL,
            confidence: Finding::CONFIDENCE_HIGH,
            scanId: $scanId,
            observedAt: $this->at('2026-03-01 09:00:00')
        );
        $repo->transitionStatus($fixed, Finding::STATUS_REMEDIATED, 'bob@acme.test');

        // A week later both deadlines (24h) have long passed.
        $overdue = $repo->overdue($this->at('2026-03-08 09:00:00'));

        $ids = array_map(static fn (Finding $f): int => $f->id(), $overdue);
        self::assertContains($open, $ids, 'An open past-due finding is overdue.');
        self::assertNotContains($fixed, $ids, 'A remediated finding is not chasing a deadline.');
    }

    // ---------------------------------------------------------------
    // AC-001 / FRD section 7 "Cross tenant"
    // ---------------------------------------------------------------

    public function test_findings_and_history_are_tenant_scoped(): void
    {
        $this->seedTenant(1);
        $this->seedTenant(2);

        $scanId = $this->scheduleScan(1);
        $id = $this->findings(1)->record(
            title: 'Exposed .git directory',
            category: Finding::CATEGORY_CONTENT_EXPOSURE,
            canonicalAsset: 'app.acme.test',
            signature: ['path' => '/.git/'],
            baseSeverity: Finding::SEVERITY_HIGH,
            confidence: Finding::CONFIDENCE_HIGH,
            scanId: $scanId
        );

        $other = $this->findings(2);

        // Another tenant sees nothing: not the finding, not its fingerprint,
        // and not one line of its history.
        self::assertNull($other->findById($id));
        self::assertSame([], $other->occurrencesFor($id));
        self::assertNull(
            $other->findByFingerprint($this->findings(1)->requireById($id)->fingerprint()),
            'A fingerprint must not leak a finding across a tenant boundary.'
        );
        self::assertSame([], $other->findByStatus(Finding::STATUS_OPEN));

        // ... and tenant 1 still sees it, so the denial is about the boundary.
        self::assertNotNull($this->findings(1)->findById($id));
        self::assertCount(1, $this->findings(1)->occurrencesFor($id));
    }

    public function test_the_same_issue_in_two_tenants_is_two_findings(): void
    {
        $this->seedTenant(1);
        $this->seedTenant(2);

        $args = [
            'title' => 'Missing HSTS',
            'category' => Finding::CATEGORY_TRANSPORT_EXPOSURE,
            'canonicalAsset' => 'shared-saas.test',
            'signature' => ['header' => 'Strict-Transport-Security'],
            'baseSeverity' => Finding::SEVERITY_MEDIUM,
            'confidence' => Finding::CONFIDENCE_HIGH,
        ];

        $one = $this->findings(1)->record(...[...$args, 'scanId' => $this->scheduleScan(1)]);
        $two = $this->findings(2)->record(...[...$args, 'scanId' => $this->scheduleScan(2)]);

        // The fingerprint is identical, but the UNIQUE key is per tenant, so
        // two clients with the same issue own two separate findings (AC-001).
        self::assertNotSame($one, $two);
        self::assertSame(
            $this->findings(1)->requireById($one)->fingerprint(),
            $this->findings(2)->requireById($two)->fingerprint()
        );
    }

    // ---------------------------------------------------------------
    // Value-object invariants
    // ---------------------------------------------------------------

    public function test_a_finding_cannot_be_last_seen_before_it_was_first_seen(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new Finding(
            1,
            1,
            str_repeat('a', 64),
            'Impossible',
            Finding::CATEGORY_OPERATIONAL_CONTROLS,
            Finding::SEVERITY_LOW,
            Finding::CONFIDENCE_LOW,
            [],
            null,
            [],
            '',
            Finding::STATUS_OPEN,
            null,
            $this->at('2026-03-08 09:00:00'),
            $this->at('2026-03-01 09:00:00'),
            1
        );
    }

    public function test_an_occurrence_older_than_the_last_does_not_rewind_the_clock(): void
    {
        $finding = new Finding(
            1,
            1,
            str_repeat('a', 64),
            'Ordered',
            Finding::CATEGORY_OPERATIONAL_CONTROLS,
            Finding::SEVERITY_LOW,
            Finding::CONFIDENCE_LOW,
            [],
            null,
            [],
            '',
            Finding::STATUS_OPEN,
            null,
            $this->at('2026-03-01 09:00:00'),
            $this->at('2026-03-08 09:00:00'),
            2
        );

        // A late-arriving old sighting still counts, but must not make the
        // finding look staler than it is.
        $updated = $finding->withOccurrence($this->at('2026-03-04 09:00:00'));
        self::assertSame('2026-03-08 09:00:00', $this->stamp($updated->lastSeenAt()));
        self::assertSame(3, $updated->occurrenceCount());
        self::assertSame('2026-03-01 09:00:00', $this->stamp($updated->firstSeenAt()));
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private function findings(int $tenantId): FindingRepository
    {
        return new FindingRepository($this->pdo, $tenantId, new AuditLogger($this->pdo));
    }

    /**
     * Builds a real authorization -> profile -> scheduled scan so an occurrence
     * can link to a legitimate scan row owned by this tenant.
     */
    private function scheduleScan(int $tenantId): int
    {
        $authId = (new AuthorizationRepository($this->pdo, $tenantId))->create(
            clientName: 'Acme Manufacturing Ltd',
            techniqueProfile: ['passive-recon'],
            stopContact: 'soc@acme.test',
            ownershipProofType: 'dns-txt',
            ownershipProofRef: 'dns TXT aiwebscapes-verify at acme.test',
            validFrom: new DateTimeImmutable('2026-01-01 00:00:00'),
            validTo: new DateTimeImmutable('2026-12-31 23:59:59')
        );
        $profiles = new ScanProfileRepository($this->pdo, $tenantId, new AuditLogger($this->pdo));
        $profileId = $profiles->create($authId, ['port-scan']);
        $profile = $profiles->requireById($profileId);

        return (new ScanRepository($this->pdo, $tenantId))
            ->schedule($authId, $profileId, $profile->version());
    }

    private function seedAsset(int $tenantId, string $canonical): int
    {
        return (new \App\SecurityAgent\AssetRepository($this->pdo, $tenantId))->upsert($canonical);
    }

    /**
     * @return list<string>
     */
    private function auditActionsFor(string $objectId): array
    {
        $statement = $this->pdo->prepare(
            'SELECT action FROM audit_events WHERE object_type = :type AND object_id = :id'
        );
        $statement->bindValue('type', 'security_finding');
        $statement->bindValue('id', $objectId);
        $statement->execute();

        $actions = [];
        foreach ($statement->fetchAll(PDO::FETCH_COLUMN) as $action) {
            if (is_string($action)) {
                $actions[] = $action;
            }
        }

        return $actions;
    }

    private function at(string $moment): DateTimeImmutable
    {
        return new DateTimeImmutable($moment, new DateTimeZone('UTC'));
    }

    private function stamp(?DateTimeImmutable $moment): string
    {
        return $moment?->format('Y-m-d H:i:s') ?? '';
    }

    private function seedTenant(int $tenantId): void
    {
        $statement = $this->pdo->prepare(
            'INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model)'
            . " VALUES (:id, :slug, :name, 'active', 'cloud')"
        );
        $statement->bindValue('id', $tenantId, PDO::PARAM_INT);
        $statement->bindValue('slug', 'finding-tenant-' . $tenantId);
        $statement->bindValue('name', 'Finding Tenant ' . $tenantId);
        $statement->execute();
    }
}
