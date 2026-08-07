<?php

declare(strict_types=1);

namespace App\Tests\Assessment;

use App\Assessment\AssessmentService;
use App\Assessment\ProhibitedRiskException;
use App\Assessment\ProcessDefectException;
use App\Tests\TestCase;

/**
 * Business-AI Assessment Framework (BAAF-001..006) + assessment scoring/reporting
 * (FR-ASMT-001/002).
 *
 * © AI WebScapes 2026
 */
final class AssessmentServiceTest extends TestCase
{
    private AssessmentService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new AssessmentService($this->pdo);
    }

    /**
     * FR-ASMT-001 — weighted composite equals BAAF Table 2.
     * Weights (verified): BV .25, Feas .20, Risk .20 (higher raw risk LOWERS
     * score), Adoption .15, Maint .10, TTV .10.
     */
    public function test_weighted_score_matches_baaf_table_2(): void
    {
        $scores = [
            'business_value' => 0.8,
            'feasibility' => 0.7,
            'risk' => 0.2,
            'adoption' => 0.6,
            'maintainability' => 0.5,
            'time_to_value' => 0.9,
        ];
        $expected = 0.8 * 0.25 + 0.7 * 0.20 + (1 - 0.2) * 0.20 + 0.6 * 0.15 + 0.5 * 0.10 + 0.9 * 0.10;

        self::assertEqualsWithDelta($expected, (new AssessmentService($this->pdo))->score($scores), 1e-9);
    }

    /** BAAF-004 — high consequence + inadequate validation is prohibited, regardless of score. */
    public function test_high_consequence_inadequate_validation_blocks(): void
    {
        $this->expectException(ProhibitedRiskException::class);
        $this->service->decide(['consequence' => 'high', 'validation' => 'inadequate']);
    }

    /** BAAF-003 — ownerless process is blocked. */
    public function test_ownerless_process_blocked(): void
    {
        $this->expectException(ProcessDefectException::class);
        $this->service->decide(['process_owner' => null]);
    }

    /**
     * BAAF §3 — a high score can NEVER override a prohibited risk combination.
     * This is the load-bearing guarantee: scoring must not paper over BAAF-004.
     */
    public function test_high_score_cannot_override_prohibited_risk(): void
    {
        $this->expectException(ProhibitedRiskException::class);
        $this->service->decide([
            'score' => 0.95,
            'consequence' => 'high',
            'validation' => 'inadequate',
        ]);
    }

    /**
     * BAAF-005 — when data quality / adoption / model / integration / benefit is
     * uncertain, the framework must REQUIRE a pilot rather than bless a go.
     */
    public function test_uncertain_benefit_requires_pilot(): void
    {
        $decision = $this->service->decide([
            'consequence' => 'low',
            'validation' => 'adequate',
            'process_owner' => 'owner-1',
            'benefit_certainty' => 'uncertain',
        ]);

        self::assertSame('pilot', $decision->disposition);
    }

    /**
     * BAAF-006 — every production use case MUST carry explicit no-go criteria and
     * a safe fallback, or the decision is refused.
     */
    public function test_missing_no_go_criteria_or_fallback_blocked(): void
    {
        $this->expectException(ProcessDefectException::class);
        $this->service->decide([
            'consequence' => 'low',
            'validation' => 'adequate',
            'process_owner' => 'owner-1',
            'benefit_certainty' => 'certain',
            // no_go_criteria + safe_fallback intentionally absent
        ]);
    }

    /** A sound, low-risk, ownerful, certain case with no-go + fallback => go. */
    public function test_sound_case_is_go(): void
    {
        $decision = $this->service->decide([
            'consequence' => 'low',
            'validation' => 'adequate',
            'process_owner' => 'owner-1',
            'benefit_certainty' => 'certain',
            'no_go_criteria' => 'accuracy below 0.90 in pilot',
            'safe_fallback' => 'route to human review queue',
        ]);

        self::assertSame('go', $decision->disposition);
    }

    /**
     * FR-ASMT-002 — generateReport() yields a VERSIONED report carrying
     * assumptions, deployment alternatives, risk classification, expected value,
     * and next actions.
     */
    public function test_report_is_versioned_and_complete(): void
    {
        $report = $this->service->generateReport([
            'title' => 'Lead routing automation',
            'scores' => [
                'business_value' => 0.8,
                'feasibility' => 0.7,
                'risk' => 0.2,
                'adoption' => 0.6,
                'maintainability' => 0.5,
                'time_to_value' => 0.9,
            ],
            'assumptions' => ['data feed stable'],
            'alternatives' => ['full manual', 'human-in-loop'],
            'expected_value' => '15h/week saved',
            'next_actions' => ['pilot 2 weeks'],
        ]);

        self::assertArrayHasKey('schema_version', $report);
        self::assertArrayHasKey('assumptions', $report);
        self::assertArrayHasKey('alternatives', $report);
        self::assertArrayHasKey('risk_classification', $report);
        self::assertArrayHasKey('expected_value', $report);
        self::assertArrayHasKey('next_actions', $report);
        self::assertArrayHasKey('composite_score', $report);
    }

    /**
     * AC-001 — assessments are tenant-scoped. A record written for tenant 1 is
     * NOT retrievable by tenant 2.
     */
    public function test_assessment_is_tenant_scoped(): void
    {
        $id = $this->service->record(tenantId: 1, title: 'A', disposition: 'go', compositeScore: 0.5);
        self::assertNotNull($this->service->get(tenantId: 1, id: $id));

        $other = $this->service->get(tenantId: 2, id: $id);
        self::assertNull($other, 'a tenant must never read another tenant’s assessment');
    }
}
