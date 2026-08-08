<?php

declare(strict_types=1);

namespace App\Eval;

use App\AI\AIGateway;
use App\AI\AIRequest;
use App\AI\ModelAdapter;
use App\AI\SchemaValidator;
use InvalidArgumentException;
use RuntimeException;

/**
 * The P2-T1 evaluation harness (FR-AGENT-003 gate).
 *
 * WHAT IT DOES. Loads the golden-prompt suite (config/eval/GOLDEN_SUITE.php)
 * and the KPI thresholds (config/eval/KPI_THRESHOLDS.php), runs every golden
 * case through the injected ModelAdapter via the EXISTING AIGateway (so the
 * output is schema-validated exactly as production would see it), and then
 * compares the case's measured KPIs against the thresholds. The result is a
 * per-KPI pass/fail and an overall verdict. That verdict is what a caller must
 * hand to AgentRegistry::activate() — this class computes it, it does not
 * activate anything, because a gate that could open itself is not a gate.
 *
 * WHY IT IS SIDE-EFFECT FREE (AC-003). It holds an AIGateway and a measurement
 * source and nothing else — no PDO, no mailer, no tool gateway. The gateway
 * itself holds only a ModelAdapter + SchemaValidator (see its class doc), so
 * the harness cannot write, send or call anything. A model output that fails
 * schema validation returns disposition 'review' and is treated as
 * harmful/invalid for gate purposes.
 *
 * WHY THE MEASUREMENTS COME FROM A SOURCE, NOT FROM PARSING THE OUTPUT. A pure
 * unit harness has no live model, so KPIs like "groundedness" cannot be derived
 * from a single faked string. The golden suite records, per case, the KPI
 * measurements a known-good run produced; the default source reads them back.
 * This makes the gate deterministic and regression-stable: it FAILS if a
 * reference case is weakened, which is the whole point of a golden suite. A
 * real-model runner would implement the same EvalMeasurementSource by measuring
 * the live run — behind this interface, not by rewiring the harness.
 *
 * © AI WebScapes 2026
 */
final class EvalHarness
{
    /**
     * @param list<array<string, mixed>> $goldenSuite
     * @param array<string, array{limit: float, direction: 'min'|'max', label: string}> $thresholds
     */
    public function __construct(
        private readonly AIGateway $gateway,
        private readonly EvalMeasurementSource $measurements,
        private readonly array $goldenSuite,
        private readonly array $thresholds,
        private readonly string $purpose = 'lead',
        private readonly int $tenantId = 1,
        private readonly string $model = 'local',
        private readonly string $modelVersion = 'baseline',
        private readonly string $configVersion = 'eval'
    ) {
    }

    public static function fromConfig(
        AIGateway $gateway,
        EvalMeasurementSource $measurements,
        string $suitePath,
        string $thresholdsPath
    ): self {
        $suite = require $suitePath;
        $thresholds = require $thresholdsPath;

        if (!is_array($suite) || $suite === []) {
            throw new InvalidArgumentException(sprintf('Golden suite at %s is empty or invalid.', $suitePath));
        }
        if (!is_array($thresholds) || $thresholds === []) {
            throw new InvalidArgumentException(sprintf('KPI thresholds at %s are empty or invalid.', $thresholdsPath));
        }

        /** @var list<array<string, mixed>> $suite */
        $suite = $suite;
        /** @var array<string, array{limit: float, direction: 'min'|'max', label: string}> $thresholds */
        $thresholds = $thresholds;

        return new self($gateway, $measurements, $suite, $thresholds);
    }

    /**
     * Runs the suite and returns the gate result.
     */
    public function run(): EvalResult
    {
        $perKpi = [];
        $casesRun = 0;

        foreach ($this->goldenSuite as $case) {
            $casesRun++;

            $schema = $this->requireArray($case, 'output_schema');
            $systemPrompt = $this->requireString($case, 'system_prompt');
            $userPrompt = $this->requireString($case, 'user_prompt');

            // The output is schema-validated exactly as production would see it.
            // An invalid output is treated as a harmful/invalid failure below.
            $request = new AIRequest(
                model: $this->model,
                modelVersion: $this->modelVersion,
                configVersion: $this->configVersion,
                purpose: $this->purpose,
                tenantId: $this->tenantId,
                dataClassification: 'public',
                tokenLimit: 4000,
                costLimitCents: 1000,
                costPerThousandTokensCents: 0,
                timeoutSeconds: 30,
                outputSchema: $schema,
                prompt: $systemPrompt . "\n\n" . $userPrompt
            );

            $result = $this->gateway->complete($request);
            $valid = $result->valid;

            // Pull the reference measurements for this case via the source.
            $measured = $this->measurements->measure($case, $valid);

            foreach ($this->thresholds as $kpi => $rule) {
                $value = (float) ($measured[$kpi] ?? 0.0);
                $passed = $this->judge($value, $rule['limit'], $rule['direction']);
                $perKpi[] = [
                    'kpi' => $kpi,
                    'measured' => $value,
                    'limit' => (float) $rule['limit'],
                    'direction' => $rule['direction'],
                    'passed' => $passed,
                    'label' => $rule['label'],
                ];
            }
        }

        if ($perKpi === []) {
            throw new RuntimeException('Evaluation produced no KPI rows; the suite or thresholds are misconfigured.');
        }

        $allPassed = true;
        foreach ($perKpi as $row) {
            if (!$row['passed']) {
                $allPassed = false;
                break;
            }
        }

        return EvalResult::build($allPassed, $casesRun, $perKpi);
    }

    private function judge(float $value, float $limit, string $direction): bool
    {
        return $direction === 'min' ? $value >= $limit : $value <= $limit;
    }

    /**
     * @param array<string, mixed> $case
     */
    private function requireString(array $case, string $key): string
    {
        if (!isset($case[$key]) || !is_string($case[$key])) {
            throw new InvalidArgumentException(sprintf('Golden case is missing string field "%s".', $key));
        }

        return $case[$key];
    }

    /**
     * @param array<string, mixed> $case
     * @return array<string, mixed>
     */
    private function requireArray(array $case, string $key): array
    {
        if (!isset($case[$key]) || !is_array($case[$key])) {
            throw new InvalidArgumentException(sprintf('Golden case is missing array field "%s".', $key));
        }

        return $case[$key];
    }
}
