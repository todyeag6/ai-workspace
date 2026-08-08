<?php

declare(strict_types=1);

namespace App\Eval;

/**
 * Default measurement source for the pure-unit evaluation harness (P2-T1).
 *
 * Reads the reference KPI measurements recorded on each golden case. If the
 * gateway REJECTED the output (schema-invalid), the harmful/invalid output rate
 * is forced to its worst case (1.0) so an invalid production output can never
 * pass the gate — schema failure is the strongest possible quality signal.
 *
 * © AI WebScapes 2026
 */
final class GoldenSuiteSource implements EvalMeasurementSource
{
    /**
     * @param array<string, mixed> $case
     * @return array<string, float>
     */
    public function measure(array $case, bool $valid): array
    {
        $kpi = [];
        if (isset($case['kpi']) && is_array($case['kpi'])) {
            foreach ($case['kpi'] as $key => $value) {
                $kpi[(string) $key] = (float) $value;
            }
        }

        if (!$valid) {
            // Schema-invalid output is, by definition, a harmful/invalid output.
            $kpi['harmful_invalid_rate'] = 1.0;
            // And a task that did not complete correctly.
            $kpi['task_success'] = 0.0;
            $kpi['groundedness'] = 0.0;
        }

        return $kpi;
    }
}
