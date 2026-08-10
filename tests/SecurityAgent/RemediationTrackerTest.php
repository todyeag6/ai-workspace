<?php

declare(strict_types=1);

namespace App\Tests\SecurityAgent;

use App\Audit\AuditLogger;
use App\SecurityAgent\AuthorizationRepository;
use App\SecurityAgent\ClosureEvidenceRequired;
use App\SecurityAgent\Evidence;
use App\SecurityAgent\EvidenceRepository;
use App\SecurityAgent\Finding;
use App\SecurityAgent\FindingRepository;
use App\SecurityAgent\HumanDecisionRequired;
use App\SecurityAgent\Remediation;
use App\SecurityAgent\RemediationRepository;
use App\SecurityAgent\RemediationTracker;
use App\SecurityAgent\Retest;
use App\SecurityAgent\RiskAcceptance;
use App\SecurityAgent\ScanProfileRepository;
use App\SecurityAgent\ScanRepository;
use App\Tests\TestCase;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

/**
 * P3-T7 - Remediation Tracker (the component after the AI Triage Assistant in
 * the FRD's order: Finding Engine -> AI Triage Assistant -> Remediation
 * Tracker -> Reporting).
 *
 * Each test maps to a baseline requirement:
 *
 *  - FRD section 2: the Remediation Tracker handles "Status, owner, comments,
 *    exceptions, due dates, retest".
 *  - FRD section 4: `remediations` (owner, plan, due, change reference,
 *    status), `risk_acceptances` (approver, rationale, controls, expiry),
 *    `retests` (profile, result, linked finding).
 *  - SFR-RETEST-001: retests shall use a defined subset/profile and link
 *    results to the original finding and remediation.
 *  - SFR-AI-001: AI shall not close findings or authorize risk acceptance
 *    without human decision.
 *  - SFR-AUD-001: changes shall be audited.
 *  - SFR-SCAN-003: tool failure shall not be interpreted as target state.
 *  - SBR-5.1: critical and high findings generate configured deadlines.
 *  - SBR-5.3: risk acceptance shall name approver, rationale, compensating
 *    control, review date, and expiry.
 *  - AC-001: no cross-tenant access. AC-002: allowlists, not denylists.
 *  - FRD section 7 "Retest" acceptance test: CLOSURE REQUIRES PASSING EVIDENCE
 *    LINKED TO REMEDIATION. This is the component's litmus and gets its own
 *    section below.
 *
 * © AI WebScapes 2026
 */
final class RemediationTrackerTest extends TestCase
{
    // ===============================================================
    // FRD section 7 - THE CLOSURE ACCEPTANCE TEST
    // "Closure requires passing evidence linked to remediation."
    //
    // Three conjunctions, so three ways to fail, each proved separately
    // and then the one way to succeed.
    // ===============================================================

    public function test_closure_is_refused_when_no_retest_exists(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);

        $this->remediations(1)->transitionStatus(
            $remediationId,
            Remediation::STATUS_IN_PROGRESS,
            'Dana Okafor'
        );
        $this->remediations(1)->transitionStatus(
            $remediationId,
            Remediation::STATUS_FIX_APPLIED,
            'Dana Okafor'
        );

        // The fix is CLAIMED. Nobody has checked it.
        try {
            $this->remediations(1)->verify($remediationId, 'Dana Okafor');
            self::fail('A remediation with no retest must not be verifiable (FRD section 7).');
        } catch (ClosureEvidenceRequired $refusal) {
            self::assertSame(ClosureEvidenceRequired::REASON_NO_RETEST, $refusal->reason());
        }

        // And the refusal actually held: nothing was written.
        $unchanged = $this->remediations(1)->findById($remediationId);
        self::assertNotNull($unchanged);
        self::assertSame(Remediation::STATUS_FIX_APPLIED, $unchanged->status());
        self::assertNull($unchanged->verifiedBy());
    }

    public function test_closure_is_refused_when_the_latest_retest_did_not_pass(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);
        $this->advanceToFixApplied(1, $remediationId);

        $this->remediations(1)->recordRetest(
            remediationId: $remediationId,
            scanProfileId: $this->profileId,
            profileVersion: 1,
            result: Retest::RESULT_FAIL,
            performedBy: 'Priya Raman',
            note: 'Still reproducible on the staging endpoint.'
        );

        try {
            $this->remediations(1)->verify($remediationId, 'Priya Raman');
            self::fail('A failed retest must not close a finding (FRD section 7).');
        } catch (ClosureEvidenceRequired $refusal) {
            self::assertSame(ClosureEvidenceRequired::REASON_NOT_PASSING, $refusal->reason());
        }
    }

    public function test_a_passing_retest_cannot_even_be_recorded_without_evidence(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);
        $this->advanceToFixApplied(1, $remediationId);

        // The third clause of FRD section 7 is enforced one layer EARLIER than
        // the other two: an unevidenced pass is refused at the point of
        // recording, so it never reaches the closure decision at all.
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/passing retest must carry evidence/i');

        $this->remediations(1)->recordRetest(
            remediationId: $remediationId,
            scanProfileId: $this->profileId,
            profileVersion: 1,
            result: Retest::RESULT_PASS,
            performedBy: 'Priya Raman'
        );
    }

    public function test_closure_succeeds_on_a_passing_retest_with_evidence_linked_to_remediation(): void
    {
        $this->seedTenant(1);
        $findingId = $this->recordFinding(1);
        $remediationId = $this->openRemediation(1, $findingId);
        $this->advanceToFixApplied(1, $remediationId);

        $evidenceId = $this->storeEvidence(1);

        $retestId = $this->remediations(1)->recordRetest(
            remediationId: $remediationId,
            scanProfileId: $this->profileId,
            profileVersion: 1,
            result: Retest::RESULT_PASS,
            performedBy: 'Priya Raman',
            evidenceId: $evidenceId,
            evidenceHash: str_repeat('a', 64),
            performedAt: $this->at('2026-04-01 10:00:00')
        );

        $this->remediations(1)->verify(
            $remediationId,
            'Priya Raman',
            null,
            $this->at('2026-04-01 11:00:00')
        );

        $verified = $this->remediations(1)->findById($remediationId);
        self::assertNotNull($verified);
        self::assertTrue($verified->isVerified());
        self::assertSame('Priya Raman', $verified->verifiedBy());
        self::assertSame('2026-04-01 11:00:00', $this->stamp($verified->verifiedAt()));

        // SFR-RETEST-001: the evidence is linked to BOTH the finding and the
        // remediation, and names the profile it ran.
        $retest = $this->remediations(1)->retests()->forRemediation($remediationId)[0];
        self::assertSame($retestId, $retest->id());
        self::assertSame($findingId, $retest->findingId());
        self::assertSame($remediationId, $retest->remediationId());
        self::assertSame($this->profileId, $retest->scanProfileId());
        self::assertSame($evidenceId, $retest->evidenceId());
        self::assertTrue($retest->closesFinding());
    }

    // ---------------------------------------------------------------
    // SFR-SCAN-003 - a tool failure is not a statement about the target
    // ---------------------------------------------------------------

    public function test_an_inconclusive_retest_closes_nothing(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);
        $this->advanceToFixApplied(1, $remediationId);

        // The scanner crashed. That is not evidence the fix worked, and it is
        // not evidence it failed either.
        $this->remediations(1)->recordRetest(
            remediationId: $remediationId,
            scanProfileId: $this->profileId,
            profileVersion: 1,
            result: Retest::RESULT_INCONCLUSIVE,
            performedBy: 'Priya Raman',
            note: 'Scanner aborted: target unreachable.'
        );

        $this->expectException(ClosureEvidenceRequired::class);
        $this->remediations(1)->verify($remediationId, 'Priya Raman');
    }

    public function test_the_latest_retest_decides_not_the_most_flattering_one(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);
        $this->advanceToFixApplied(1, $remediationId);

        // It passed in March...
        $this->remediations(1)->recordRetest(
            remediationId: $remediationId,
            scanProfileId: $this->profileId,
            profileVersion: 1,
            result: Retest::RESULT_PASS,
            performedBy: 'Priya Raman',
            evidenceId: $this->storeEvidence(1),
            performedAt: $this->at('2026-03-01 10:00:00')
        );

        // ...and regressed in June.
        $this->remediations(1)->recordRetest(
            remediationId: $remediationId,
            scanProfileId: $this->profileId,
            profileVersion: 1,
            result: Retest::RESULT_FAIL,
            performedBy: 'Priya Raman',
            performedAt: $this->at('2026-06-01 10:00:00')
        );

        // A stale success must not outrank current evidence of failure.
        try {
            $this->remediations(1)->verify($remediationId, 'Priya Raman');
            self::fail('The most recent retest must decide closure, not the best one.');
        } catch (ClosureEvidenceRequired $refusal) {
            self::assertSame(ClosureEvidenceRequired::REASON_NOT_PASSING, $refusal->reason());
        }
    }

    public function test_a_failing_retest_walks_a_claimed_fix_back_to_in_progress(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);
        $this->advanceToFixApplied(1, $remediationId);

        $this->remediations(1)->recordRetest(
            remediationId: $remediationId,
            scanProfileId: $this->profileId,
            profileVersion: 1,
            result: Retest::RESULT_FAIL,
            performedBy: 'Priya Raman'
        );

        self::assertSame(
            Remediation::STATUS_IN_PROGRESS,
            $this->remediations(1)->findById($remediationId)?->status(),
            'A fix that failed its retest is not applied; it is back in progress.'
        );

        // ...but the failed retest is still in the history.
        self::assertCount(1, $this->remediations(1)->retests()->forRemediation($remediationId));
    }

    public function test_verified_cannot_be_reached_through_the_status_back_door(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);
        $this->advanceToFixApplied(1, $remediationId);

        // Even with a named human and a legal-looking transition, the generic
        // status path refuses: verification needs evidence, not just a decider.
        $this->expectException(ClosureEvidenceRequired::class);

        $this->remediations(1)->transitionStatus(
            $remediationId,
            Remediation::STATUS_VERIFIED,
            'Dana Okafor'
        );
    }

    // ---------------------------------------------------------------
    // SFR-AI-001 - closing and accepting risk are human decisions
    // ---------------------------------------------------------------

    public function test_verification_without_a_named_human_is_refused(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);
        $this->advanceToFixApplied(1, $remediationId);
        $this->remediations(1)->recordRetest(
            remediationId: $remediationId,
            scanProfileId: $this->profileId,
            profileVersion: 1,
            result: Retest::RESULT_PASS,
            performedBy: 'Priya Raman',
            evidenceId: $this->storeEvidence(1)
        );

        // The evidence is there. The human is not.
        $this->expectException(HumanDecisionRequired::class);
        $this->remediations(1)->verify($remediationId, '   ');
    }

    public function test_risk_acceptance_without_a_named_approver_is_refused(): void
    {
        $this->seedTenant(1);
        $findingId = $this->recordFinding(1);

        $this->expectException(HumanDecisionRequired::class);

        $this->remediations(1)->acceptRisk(
            findingId: $findingId,
            approver: '',
            rationale: 'Compensating WAF rule in place.',
            compensatingControl: 'WAF rule 1042 blocks the vector.'
        );
    }

    public function test_a_retest_must_name_the_human_who_performed_it(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/must name the human/i');

        $this->remediations(1)->recordRetest(
            remediationId: $remediationId,
            scanProfileId: $this->profileId,
            profileVersion: 1,
            result: Retest::RESULT_FAIL,
            performedBy: ''
        );
    }

    // ---------------------------------------------------------------
    // SBR-5.3 - risk acceptance names five things, and expires
    // ---------------------------------------------------------------

    public function test_risk_acceptance_records_all_five_required_elements(): void
    {
        $this->seedTenant(1);
        $findingId = $this->recordFinding(1);

        $id = $this->remediations(1)->acceptRisk(
            findingId: $findingId,
            approver: 'Helen Vasquez (CISO)',
            rationale: 'The affected endpoint is decommissioned in Q4.',
            compensatingControl: 'WAF rule 1042 blocks the vector; monitored weekly.',
            grantedAt: $this->at('2026-04-01 09:00:00')
        );

        $acceptance = $this->remediations(1)->riskAcceptances()->findById($id);
        self::assertNotNull($acceptance);

        // All five clauses of SBR-5.3, present and readable.
        self::assertSame('Helen Vasquez (CISO)', $acceptance->approver());
        self::assertSame('The affected endpoint is decommissioned in Q4.', $acceptance->rationale());
        self::assertStringContainsString('WAF rule 1042', $acceptance->compensatingControl());
        self::assertSame('2026-05-31 09:00:00', $this->stamp($acceptance->reviewAt()));
        self::assertSame('2026-06-30 09:00:00', $this->stamp($acceptance->expiresAt()));

        // The default window is the ratified 90 days, reviewed 30 days before.
        self::assertTrue($acceptance->isActiveAt($this->at('2026-05-01 09:00:00')));
    }

    #[DataProvider('blankAcceptanceElements')]
    public function test_a_risk_acceptance_missing_any_required_element_is_refused(
        string $rationale,
        string $control
    ): void {
        $this->seedTenant(1);
        $findingId = $this->recordFinding(1);

        $this->expectException(InvalidArgumentException::class);

        $this->remediations(1)->acceptRisk(
            findingId: $findingId,
            approver: 'Helen Vasquez',
            rationale: $rationale,
            compensatingControl: $control
        );
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function blankAcceptanceElements(): array
    {
        return [
            'no rationale' => ['', 'WAF rule 1042.'],
            'no compensating control' => ['Decommissioned in Q4.', ''],
            'neither' => ['   ', '   '],
        ];
    }

    public function test_an_expired_acceptance_stops_suppressing_the_finding_without_a_batch_job(): void
    {
        $this->seedTenant(1);
        $findingId = $this->recordFinding(1);

        $this->remediations(1)->acceptRisk(
            findingId: $findingId,
            approver: 'Helen Vasquez',
            rationale: 'Decommissioned in Q4.',
            compensatingControl: 'WAF rule 1042.',
            grantedAt: $this->at('2026-04-01 09:00:00')
        );

        // Nothing ran in between. The passage of time alone is sufficient.
        self::assertTrue($this->remediations(1)->isRiskAccepted($findingId, $this->at('2026-06-29 09:00:00')));
        self::assertFalse($this->remediations(1)->isRiskAccepted($findingId, $this->at('2026-07-01 09:00:00')));
    }

    public function test_an_acceptance_beyond_the_ratified_ceiling_is_refused_not_clamped(): void
    {
        $this->seedTenant(1);
        $findingId = $this->recordFinding(1);

        // A caller asking for three years and silently receiving one would
        // believe the risk was accepted for three years.
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/may not run longer than 365 days/');

        $this->remediations(1)->acceptRisk(
            findingId: $findingId,
            approver: 'Helen Vasquez',
            rationale: 'Long-term architectural constraint.',
            compensatingControl: 'Network segmentation.',
            requestedExpiry: $this->at('2029-04-01 09:00:00'),
            grantedAt: $this->at('2026-04-01 09:00:00')
        );
    }

    public function test_a_revoked_acceptance_keeps_its_original_terms_readable(): void
    {
        $this->seedTenant(1);
        $findingId = $this->recordFinding(1);

        $id = $this->remediations(1)->acceptRisk(
            findingId: $findingId,
            approver: 'Helen Vasquez',
            rationale: 'Decommissioned in Q4.',
            compensatingControl: 'WAF rule 1042.',
            grantedAt: $this->at('2026-04-01 09:00:00')
        );

        self::assertTrue($this->remediations(1)->revokeRisk(
            $id,
            'Helen Vasquez',
            'Decommissioning slipped; fixing instead.',
            $this->at('2026-05-01 09:00:00')
        ));

        $acceptance = $this->remediations(1)->riskAcceptances()->findById($id);
        self::assertNotNull($acceptance);
        self::assertSame(RiskAcceptance::STATUS_REVOKED, $acceptance->status());
        self::assertSame('Helen Vasquez', $acceptance->revokedBy());
        // The original decision survives its own withdrawal.
        self::assertSame('Decommissioned in Q4.', $acceptance->rationale());
        self::assertFalse($acceptance->isActiveAt($this->at('2026-05-02 09:00:00')));
    }

    public function test_acceptances_needing_review_are_listed_before_they_lapse(): void
    {
        $tracker = new RemediationTracker();
        $window = $tracker->acceptanceWindow($this->at('2026-04-01 09:00:00'));

        $acceptance = new RiskAcceptance(
            1,
            1,
            1,
            'Helen Vasquez',
            'Decommissioned in Q4.',
            'WAF rule 1042.',
            $window['review_at'],
            $window['expires_at'],
            RiskAcceptance::STATUS_ACTIVE,
            $this->at('2026-04-01 09:00:00')
        );

        // Before the review date: not yet owed.
        self::assertSame([], $tracker->acceptancesNeedingReview([$acceptance], $this->at('2026-05-01 09:00:00')));
        // On the review date, still live: owed, and there is time to act.
        self::assertCount(1, $tracker->acceptancesNeedingReview([$acceptance], $this->at('2026-06-01 09:00:00')));
        self::assertTrue($acceptance->isActiveAt($this->at('2026-06-01 09:00:00')));
    }

    // ---------------------------------------------------------------
    // SBR-5.1 / FRD section 4 - the deadline is inherited, not invented
    // ---------------------------------------------------------------

    public function test_the_remediation_inherits_the_findings_own_sla_deadline(): void
    {
        $this->seedTenant(1);
        $findingId = $this->recordFinding(1, Finding::SEVERITY_HIGH, '2026-03-01 09:00:00');
        $finding = $this->findings(1)->requireById($findingId);

        $remediationId = $this->openRemediation(1, $findingId);
        $remediation = $this->remediations(1)->findById($remediationId);

        self::assertNotNull($remediation);
        self::assertNotNull($finding->slaDueAt());
        self::assertSame(
            $this->stamp($finding->slaDueAt()),
            $this->stamp($remediation->dueAt()),
            'A remediation must not carry a looser deadline than the finding it fixes (SBR-5.1).'
        );
    }

    public function test_moving_a_deadline_requires_a_human_and_a_stated_reason(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);

        try {
            $this->remediations(1)->reschedule(
                $remediationId,
                $this->at('2026-12-01 09:00:00'),
                'Dana Okafor',
                ''
            );
            self::fail('A moved security deadline with no stated reason must be refused.');
        } catch (RuntimeException $refusal) {
            self::assertStringContainsString('stated reason', $refusal->getMessage());
        }
    }

    public function test_overdue_lists_only_open_remediations_past_their_deadline(): void
    {
        $this->seedTenant(1);
        $findingId = $this->recordFinding(1, Finding::SEVERITY_HIGH, '2026-03-01 09:00:00');
        $remediationId = $this->openRemediation(1, $findingId);

        // A high finding's SLA is 72 hours from first sighting.
        self::assertSame([], $this->remediations(1)->overdue($this->at('2026-03-02 09:00:00')));
        self::assertCount(1, $this->remediations(1)->overdue($this->at('2026-03-10 09:00:00')));

        // Cancelling it stops the clock: the work is not happening and
        // something else accounts for it.
        $this->remediations(1)->transitionStatus(
            $remediationId,
            Remediation::STATUS_CANCELLED,
            'Dana Okafor'
        );
        self::assertSame([], $this->remediations(1)->overdue($this->at('2026-03-10 09:00:00')));
    }

    // ---------------------------------------------------------------
    // AC-002 - allowlists, not denylists
    // ---------------------------------------------------------------

    public function test_an_unknown_status_is_refused_rather_than_stored(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);

        $this->expectException(RuntimeException::class);

        $this->remediations(1)->transitionStatus($remediationId, 'mostly_done', 'Dana Okafor');
    }

    public function test_an_unknown_retest_result_is_refused_rather_than_stored(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/allowlist, AC-002/');

        $this->remediations(1)->recordRetest(
            remediationId: $remediationId,
            scanProfileId: $this->profileId,
            profileVersion: 1,
            result: 'probably_fine',
            performedBy: 'Priya Raman'
        );
    }

    public function test_a_verified_remediation_is_terminal(): void
    {
        $tracker = new RemediationTracker();

        // Nothing leads out of verified: a regression is a NEW occurrence on
        // the finding, not a rewrite of the fix that did work.
        self::assertFalse($tracker->mayTransition(
            Remediation::STATUS_VERIFIED,
            Remediation::STATUS_IN_PROGRESS
        ));
        self::assertFalse($tracker->mayTransition(
            Remediation::STATUS_CANCELLED,
            Remediation::STATUS_IN_PROGRESS
        ));
        self::assertTrue($tracker->mayTransition(
            Remediation::STATUS_PLANNED,
            Remediation::STATUS_IN_PROGRESS
        ));
    }

    // ---------------------------------------------------------------
    // AC-001 - no cross-tenant access
    // ---------------------------------------------------------------

    public function test_a_remediation_is_invisible_to_another_tenant(): void
    {
        $this->seedTenant(1);
        $this->seedTenant(2);
        $remediationId = $this->openRemediationForNewFinding(1);

        // Absent and forbidden are deliberately indistinguishable.
        self::assertNull($this->remediations(2)->findById($remediationId));
        self::assertSame([], $this->remediations(2)->all());

        $this->expectException(RuntimeException::class);
        $this->remediations(2)->verify($remediationId, 'Mallory');
    }

    public function test_a_retest_cannot_be_recorded_against_another_tenants_remediation(): void
    {
        $this->seedTenant(1);
        $this->seedTenant(2);
        $remediationId = $this->openRemediationForNewFinding(1);

        $this->expectException(RuntimeException::class);

        $this->remediations(2)->recordRetest(
            remediationId: $remediationId,
            scanProfileId: $this->profileId,
            profileVersion: 1,
            result: Retest::RESULT_FAIL,
            performedBy: 'Mallory'
        );
    }

    // ---------------------------------------------------------------
    // SFR-AUD-001 - decisions are audited
    // ---------------------------------------------------------------

    public function test_every_remediation_decision_is_audited(): void
    {
        $this->seedTenant(1);
        $findingId = $this->recordFinding(1);
        $remediationId = $this->openRemediation(1, $findingId);
        $this->advanceToFixApplied(1, $remediationId);

        $this->remediations(1)->recordRetest(
            remediationId: $remediationId,
            scanProfileId: $this->profileId,
            profileVersion: 1,
            result: Retest::RESULT_PASS,
            performedBy: 'Priya Raman',
            evidenceId: $this->storeEvidence(1)
        );
        $this->remediations(1)->verify($remediationId, 'Priya Raman');
        $this->remediations(1)->comment($remediationId, 'Dana Okafor', 'Deployed in release 4.2.1.');

        $actions = $this->auditActionsFor('remediation', (string) $remediationId);

        self::assertContains(RemediationRepository::AUDIT_OPEN, $actions);
        self::assertContains(RemediationRepository::AUDIT_STATUS, $actions);
        self::assertContains(RemediationRepository::AUDIT_RETEST, $actions);
        self::assertContains(RemediationRepository::AUDIT_VERIFY, $actions);
        self::assertContains(RemediationRepository::AUDIT_COMMENT, $actions);
    }

    public function test_a_decision_refuses_to_run_when_it_cannot_be_audited(): void
    {
        $this->seedTenant(1);
        $findingId = $this->recordFinding(1);
        $finding = $this->findings(1)->requireById($findingId);

        // No AuditLogger injected: fail closed rather than make an
        // unevidenced change (SFR-AUD-001).
        $unaudited = new RemediationRepository($this->pdo, 1);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/AuditLogger must be injected/');

        $unaudited->open($finding, 'Platform Team', 'Dana Okafor');
    }

    // ---------------------------------------------------------------
    // FRD section 2 - comments, and the append-only history
    // ---------------------------------------------------------------

    public function test_comments_are_recorded_in_order_with_their_authors(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);

        $this->remediations(1)->comment(
            $remediationId,
            'Dana Okafor',
            'Reproduced on staging.',
            $this->at('2026-04-01 09:00:00')
        );
        $this->remediations(1)->comment(
            $remediationId,
            'Priya Raman',
            'Patch queued for release 4.2.1.',
            $this->at('2026-04-02 09:00:00')
        );

        $thread = $this->remediations(1)->comments()->forRemediation($remediationId);

        self::assertCount(2, $thread);
        self::assertSame('Dana Okafor', $thread[0]['author']);
        self::assertSame('Priya Raman', $thread[1]['author']);
        self::assertSame('Patch queued for release 4.2.1.', $thread[1]['body']);
    }

    public function test_an_anonymous_comment_is_refused(): void
    {
        $this->seedTenant(1);
        $remediationId = $this->openRemediationForNewFinding(1);

        $this->expectException(InvalidArgumentException::class);
        $this->remediations(1)->comment($remediationId, '  ', 'Looks fine to me.');
    }

    public function test_opening_a_plan_twice_returns_the_same_plan(): void
    {
        $this->seedTenant(1);
        $findingId = $this->recordFinding(1);

        $first = $this->openRemediation(1, $findingId);
        $second = $this->openRemediation(1, $findingId);

        // Re-observing an issue must not error just because somebody already
        // started fixing it.
        self::assertSame($first, $second);
        self::assertCount(1, $this->remediations(1)->all());
    }

    // ---------------------------------------------------------------
    // The policy file is a contract term, not a convenience
    // ---------------------------------------------------------------

    public function test_shipped_remediation_policy_pins_its_contract_terms(): void
    {
        /** @var mixed $policy */
        $policy = require dirname(__DIR__, 2) . '/config/security/REMEDIATION_POLICY.php';

        self::assertIsArray($policy);

        // These numbers encode a contract term (SBR-5.3). Changing one without
        // a cited source and a ratification should fail CI, which is what this
        // test is for.
        self::assertSame(365, $policy['max_acceptance_days'] ?? null);
        self::assertSame(90, $policy['default_acceptance_days'] ?? null);
        self::assertSame(30, $policy['review_lead_days'] ?? null);

        $tracker = new RemediationTracker();
        self::assertSame(365, $tracker->maxAcceptanceDays());
        self::assertSame(90, $tracker->defaultAcceptanceDays());
        self::assertSame(30, $tracker->reviewLeadDays());
    }

    public function test_an_incoherent_policy_is_refused_at_construction(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/cannot exceed the maximum/');

        // A default longer than the ceiling would grant waivers the policy
        // forbids. Fail closed rather than pick one.
        new RemediationTracker([
            'max_acceptance_days' => 30,
            'default_acceptance_days' => 90,
            'review_lead_days' => 7,
        ]);
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private int $profileId = 0;

    private function remediations(int $tenantId): RemediationRepository
    {
        return new RemediationRepository($this->pdo, $tenantId, new AuditLogger($this->pdo));
    }

    private function findings(int $tenantId): FindingRepository
    {
        return new FindingRepository($this->pdo, $tenantId, new AuditLogger($this->pdo));
    }

    /**
     * Records a real finding through the Finding Engine, so the remediation
     * has a genuine SLA to inherit.
     */
    private function recordFinding(
        int $tenantId,
        string $severity = Finding::SEVERITY_HIGH,
        string $observedAt = '2026-03-01 09:00:00'
    ): int {
        $scanId = $this->scheduleScan($tenantId);

        return $this->findings($tenantId)->record(
            title: 'TLS 1.0 accepted on public endpoint',
            category: Finding::CATEGORY_TRANSPORT_EXPOSURE,
            canonicalAsset: 'app.acme.test',
            signature: ['protocol' => 'TLSv1.0', 'port' => 443],
            baseSeverity: $severity,
            confidence: Finding::CONFIDENCE_HIGH,
            scanId: $scanId,
            observedAt: $this->at($observedAt)
        );
    }

    private function openRemediation(int $tenantId, int $findingId): int
    {
        $finding = $this->findings($tenantId)->requireById($findingId);

        return $this->remediations($tenantId)->open(
            $finding,
            'Platform Team',
            'Dana Okafor',
            'Disable TLS 1.0 at the load balancer.',
            'CHG-2026-0412',
            $this->at('2026-03-01 12:00:00')
        );
    }

    private function openRemediationForNewFinding(int $tenantId): int
    {
        return $this->openRemediation($tenantId, $this->recordFinding($tenantId));
    }

    private function advanceToFixApplied(int $tenantId, int $remediationId): void
    {
        $this->remediations($tenantId)->transitionStatus(
            $remediationId,
            Remediation::STATUS_IN_PROGRESS,
            'Dana Okafor'
        );
        $this->remediations($tenantId)->transitionStatus(
            $remediationId,
            Remediation::STATUS_FIX_APPLIED,
            'Dana Okafor'
        );
    }

    /**
     * Stores a real evidence row so a passing retest can link to one.
     */
    private function storeEvidence(int $tenantId): int
    {
        $scanId = $this->scheduleScan($tenantId);

        return (new EvidenceRepository($this->pdo, $tenantId))->store(new Evidence(
            $tenantId,
            0,
            $scanId,
            null,
            'tls-probe',
            '1.4.2',
            'app.acme.test:443',
            $this->at('2026-04-01 10:00:00'),
            'transport',
            ['tls_version' => 'TLSv1.2', 'cipher' => 'ECDHE-RSA-AES128-GCM-SHA256'],
            null,
            str_repeat('a', 64),
            $this->at('2026-04-01 10:00:00'),
            []
        ));
    }

    /**
     * Builds a real authorization -> profile -> scheduled scan so a retest can
     * name a legitimate profile owned by this tenant.
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

        $this->profileId = $profileId;

        return (new ScanRepository($this->pdo, $tenantId))
            ->schedule($authId, $profileId, $profile->version());
    }

    /**
     * @return list<string>
     */
    private function auditActionsFor(string $objectType, string $objectId): array
    {
        $statement = $this->pdo->prepare(
            'SELECT action FROM audit_events WHERE object_type = :type AND object_id = :id'
        );
        $statement->bindValue('type', $objectType);
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
        $statement->bindValue('slug', 'remediation-tenant-' . $tenantId);
        $statement->bindValue('name', 'Remediation Tenant ' . $tenantId);
        $statement->execute();
    }
}
