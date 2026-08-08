<?php

declare(strict_types=1);

namespace App\Eval;

use RuntimeException;

/**
 * The result of one evaluation run over the golden suite (P2-T1).
 *
 * Immutable: built only from arrays produced by EvalHarness, never mutated
 * back. Holds each KPI's measured value, the threshold it was judged against,
 * and whether it passed — so a gate caller can log exactly which measure failed
 * rather than a bare boolean.
 *
 * © AI WebScapes 2026
 */
final class EvalResult
{
    /**
     * @param list<array{
     *     kpi: string,
     *     measured: float,
     *     limit: float,
     *     direction: 'min'|'max',
     *     passed: bool,
     *     label: string
     * }> $perKpi
     */
    private function __construct(
        private readonly bool $passed,
        private readonly int $casesRun,
        private readonly array $perKpi
    ) {
    }

    /**
     * @param list<array{
     *     kpi: string,
     *     measured: float,
     *     limit: float,
     *     direction: 'min'|'max',
     *     passed: bool,
     *     label: string
     * }> $perKpi
     */
    public static function build(bool $passed, int $casesRun, array $perKpi): self
    {
        return new self($passed, $casesRun, $perKpi);
    }

    public function passed(): bool
    {
        return $this->passed;
    }

    public function casesRun(): int
    {
        return $this->casesRun;
    }

    /**
     * @return list<array{
     *     kpi: string,
     *     measured: float,
     *     limit: float,
     *     direction: 'min'|'max',
     *     passed: bool,
     *     label: string
     * }>
     */
    public function perKpi(): array
    {
        return $this->perKpi;
    }

    /**
     * The KPI keys that failed, for logging the gate reason.
     *
     * @return list<string>
     */
    public function failedKpis(): array
    {
        $failed = [];
        foreach ($this->perKpi as $row) {
            if (!$row['passed']) {
                $failed[] = $row['kpi'];
            }
        }

        return $failed;
    }

    /**
     * @throws RuntimeException When the run carried no KPI rows (misconfigured).
     */
    public function requirePassed(): void
    {
        if (!$this->passed) {
            throw new RuntimeException(sprintf(
                'Evaluation did not pass the release gate. Failed KPIs: %s.',
                implode(', ', $this->failedKpis())
            ));
        }
    }
}
