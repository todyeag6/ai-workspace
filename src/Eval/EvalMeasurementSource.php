<?php

declare(strict_types=1);

namespace App\Eval;

use App\AI\AIResult;

/**
 * Supplies the measured KPI values for one golden case (P2-T1).
 *
 * In a PURE UNIT harness there is no live model, so a "measurement" is the
 * reference value the golden suite records for a known-good run. GoldenSuiteSource
 * reads those back, which makes the gate deterministic and regression-stable.
 *
 * A REAL-MODEL runner (out of scope for P2-T1) would implement this same
 * interface by measuring the live output — e.g. a groundedness scorer over the
 * produced text, an override/escalation counter, a cost meter. Swapping the
 * source is the ONLY change needed; the harness, the gate and the thresholds
 * stay identical.
 *
 * © AI WebScapes 2026
 */
interface EvalMeasurementSource
{
    /**
     * @param array<string, mixed> $case The golden case (carries its reference `kpi`).
     * @param bool                  $valid Whether the gateway accepted the output as schema-valid.
     * @return array<string, float> KPI key => measured value.
     */
    public function measure(array $case, bool $valid): array;
}
