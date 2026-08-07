<?php

declare(strict_types=1);

namespace App\Assessment;

/**
 * The outcome of an AssessmentService::decide() evaluation.
 *
 * @property-read string $disposition  One of 'go' | 'pilot' | 'no-go'.
 * @property-read string $rationale    Why this disposition was reached.
 *
 * © AI WebScapes 2026
 */
final class Decision
{
    public function __construct(
        public readonly string $disposition,
        public readonly string $rationale
    ) {
    }
}
