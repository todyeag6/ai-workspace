<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use RuntimeException;

/**
 * Thrown when a caller tries to close or verify a finding without the passing,
 * evidence-bearing retest that FRD section 7 requires.
 *
 * THE ACCEPTANCE TEST THIS ENFORCES, VERBATIM
 * --------------------------------------------
 * FRD section 7, "Retest" row: "Closure requires passing evidence linked to
 * remediation."
 *
 * WHY AN EXCEPTION AND NOT A BOOLEAN. Identical reasoning to
 * HumanDecisionRequired: a false is a result a caller may ignore, and the
 * caller here is the party that wants the finding closed. A thrown refusal
 * fails closed — the write does not happen and the caller is told why.
 *
 * Carries the REASON the closure was refused so the message is actionable: an
 * operator reading it learns whether there was no retest at all, whether the
 * retest failed, or whether it passed but carried no evidence — three
 * different next actions.
 *
 * © AI WebScapes 2026
 */
final class ClosureEvidenceRequired extends RuntimeException
{
    /** No retest has been recorded against this remediation. */
    public const REASON_NO_RETEST = 'no_retest';

    /** A retest exists but its most recent result is not a pass. */
    public const REASON_NOT_PASSING = 'not_passing';

    /** A passing retest exists but carries no evidence artefact. */
    public const REASON_NO_EVIDENCE = 'no_evidence';

    public function __construct(
        private readonly string $reason,
        private readonly int $findingId,
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Which of the three closure conditions was not met.
     */
    public function reason(): string
    {
        return $this->reason;
    }

    /**
     * The finding whose closure was refused.
     */
    public function findingId(): int
    {
        return $this->findingId;
    }
}
