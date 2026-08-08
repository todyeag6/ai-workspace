<?php

declare(strict_types=1);

namespace App\Tests\Eval;

use App\AI\AIRequest;
use App\AI\AIResult;
use App\AI\AIGateway;
use App\AI\ModelAdapter;
use App\AI\SchemaValidator;
use App\Eval\EvalHarness;
use App\Eval\EvalMeasurementSource;
use App\Eval\EvalResult;
use App\Eval\GoldenSuiteSource;
use PHPUnit\Framework\TestCase;

/**
 * P2-T1 evaluation harness (FR-AGENT-003 gate component).
 *
 * PURE unit tests: the "model" is a faked ModelAdapter, so there is no network
 * and no real model. The harness must (a) enforce the KPI thresholds defined in
 * config/eval/KPI_THRESHOLDS.php, (b) treat a schema-invalid output as a
 * harmful/invalid failure, and (c) return a verdict a release gate can act on.
 *
 * The regression value is in test_closing_one_threshold_fails_the_gate: it
 * proves the gate is not vacuous - weaken a measured KPI and the whole run
 * fails, which is exactly what a golden suite is for.
 *
 * © AI WebScapes 2026
 */
final class EvalHarnessTest extends TestCase
{
    /**
     * A fake adapter that returns the given raw JSON. Deterministic and
     * network-free, like the fakes in tests/AI/AIGatewayTest.php.
     */
    private function adapterReturning(string $raw): ModelAdapter
    {
        return new class ($raw) implements ModelAdapter {
            public function __construct(private readonly string $raw)
            {
            }

            public function generate(AIRequest $request): string
            {
                return $this->raw;
            }
        };
    }

    /**
     * A measurement source that returns fixed KPI values, so a test can dial a
     * KPI to failing without touching the golden suite file.
     *
     * @param array<string, float> $values
     */
    private function fixedSource(array $values): EvalMeasurementSource
    {
        return new class ($values) implements EvalMeasurementSource {
            /**
             * @param array<string, float> $values
             */
            public function __construct(private readonly array $values)
            {
            }

            public function measure(array $case, bool $valid): array
            {
                return $this->values;
            }
        };
    }

    /**
     * @return array<string, mixed>
     */
    private function schema(): array
    {
        return [
            'verdict' => 'string',
            'confidence' => 'float',
        ];
    }

    private function harnessWith(ModelAdapter $adapter, EvalMeasurementSource $source): EvalHarness
    {
        $thresholds = require __DIR__ . '/../../config/eval/KPI_THRESHOLDS.php';
        $suite = [
            [
                'id' => 'case_a',
                'system_prompt' => 'sys',
                'user_prompt' => 'usr',
                'output_schema' => $this->schema(),
                'kpi' => [],
            ],
        ];

        return new EvalHarness(
            new AIGateway($adapter, new SchemaValidator()),
            $source,
            $suite,
            $thresholds
        );
    }

    public function test_passing_measurements_clear_the_gate(): void
    {
        $adapter = $this->adapterReturning('{"verdict":"New"}');
        // Every measured KPI is comfortably inside the proposed thresholds.
        $source = $this->fixedSource([
            'task_success' => 1.0,
            'groundedness' => 1.0,
            'human_override_rate' => 0.0,
            'escalation_rate' => 0.0,
            'harmful_invalid_rate' => 0.0,
            'cost_cents_per_outcome' => 0.0,
        ]);

        $result = $this->harnessWith($adapter, $source)->run();

        self::assertInstanceOf(EvalResult::class, $result);
        self::assertTrue($result->passed(), 'All KPIs inside threshold must pass.');
        self::assertSame(1, $result->casesRun());
        self::assertSame([], $result->failedKpis());
    }

    public function test_closing_one_threshold_fails_the_gate(): void
    {
        $adapter = $this->adapterReturning('{"verdict":"New"}');
        // task_success 0.50 violates the proposed >= 0.90 minimum.
        $source = $this->fixedSource([
            'task_success' => 0.50,
            'groundedness' => 1.0,
            'human_override_rate' => 0.0,
            'escalation_rate' => 0.0,
            'harmful_invalid_rate' => 0.0,
            'cost_cents_per_outcome' => 0.0,
        ]);

        $result = $this->harnessWith($adapter, $source)->run();

        self::assertFalse($result->passed(), 'A breached threshold must fail the gate.');
        self::assertContains('task_success', $result->failedKpis());
    }

    public function test_schema_invalid_output_is_harmful_and_fails(): void
    {
        // Output that does not match the schema -> gateway returns disposition
        // 'review' (invalid). GoldenSuiteSource forces harmful_invalid_rate to
        // 1.0 on invalid output, which breaches the <= 0.01 ceiling.
        $adapter = $this->adapterReturning('{"nope":true}');
        $source = new GoldenSuiteSource();

        $result = $this->harnessWith($adapter, $source)->run();

        self::assertFalse($result->passed(), 'Schema-invalid output must fail the gate.');
        self::assertContains('harmful_invalid_rate', $result->failedKpis());
    }

    public function test_eval_result_records_each_failing_kpi(): void
    {
        $adapter = $this->adapterReturning('{"verdict":"New"}');
        $source = $this->fixedSource([
            'task_success' => 1.0,
            'groundedness' => 1.0,
            'human_override_rate' => 0.99, // > 0.20 ceiling
            'escalation_rate' => 0.99,    // > 0.15 ceiling
            'harmful_invalid_rate' => 0.0,
            'cost_cents_per_outcome' => 0.0,
        ]);

        $result = $this->harnessWith($adapter, $source)->run();
        $failed = $result->failedKpis();

        self::assertContains('human_override_rate', $failed);
        self::assertContains('escalation_rate', $failed);
        self::assertNotContains('task_success', $failed);
    }
}
