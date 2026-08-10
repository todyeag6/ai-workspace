<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use RuntimeException;

/**
 * Thrown when a caller tries to reach a finding state that SFR-AI-001 reserves
 * for a human decision, without naming the human who made it.
 *
 * WHY THIS IS AN EXCEPTION AND NOT A RETURN VALUE. SFR-AI-001 says AI "shall
 * not alter confirmed status, close findings, or authorize risk acceptance
 * without human decision". A boolean false would be a result a caller may
 * ignore; a thrown refusal is not. Fail closed: the write does not happen and
 * the caller finds out.
 *
 * Carries the ATTEMPTED status so the refusal is actionable - the caller (or
 * the operator reading the log) can see exactly which transition needed a
 * human and go and get one, rather than receiving a bare "no".
 *
 * © AI WebScapes 2026
 */
final class HumanDecisionRequired extends RuntimeException
{
    public function __construct(
        private readonly string $attemptedStatus,
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * The status the caller tried to reach without a human decision.
     */
    public function attemptedStatus(): string
    {
        return $this->attemptedStatus;
    }
}
