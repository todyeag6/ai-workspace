<?php

declare(strict_types=1);

namespace App\Assessment;

use DomainException;

/**
 * BAAF-004 / BAAF §3 — a use case pairs high consequence with inadequate
 * validation or reversal, so autonomous execution is prohibited. A high score
 * never overrides this.
 *
 * © AI WebScapes 2026
 */
final class ProhibitedRiskException extends DomainException
{
}
