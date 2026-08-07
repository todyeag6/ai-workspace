<?php

declare(strict_types=1);

namespace App\AI;

use RuntimeException;

/**
 * Thrown when something asks a model output to authorise an action whose
 * impact is too high for a machine to sign off alone (FR-AI-006).
 *
 * WHY A THROW AND NOT A false RETURN: the caller of an authorisation check is,
 * by definition, about to do the thing. A boolean that goes unread still
 * leaves the transfer, the deletion or the contract signed; an exception stops
 * the code path before the effect and cannot be ignored by omission.
 *
 * The message never contains the model output, only its type. The refusal does
 * not depend on the content - quoting it back would invite the reader to
 * argue with a decision that is deliberately content-blind, and would copy
 * possibly sensitive material into logs.
 *
 * Extends RuntimeException for the same reason as BudgetExceeded and
 * ReleaseGateNotMet: one refusal, not a hierarchy.
 *
 * © AI WebScapes 2026
 */
final class AutonomousActionRejected extends RuntimeException
{
    public static function highImpact(string $riskClass, string $outputType): self
    {
        return new self(sprintf(
            'Refusing to let model output (%s) authorise a "%s" risk transaction. '
            . 'FR-AI-006 requires a separate policy or a human decision for '
            . 'high-impact actions, and the refusal is independent of what the '
            . 'model said: a confident output is not an authorisation.',
            $outputType,
            $riskClass
        ));
    }

    public static function unknownRiskClass(string $riskClass): self
    {
        return new self(sprintf(
            'Refusing to authorise an action of unknown risk class "%s". An '
            . 'unclassified action is treated as high impact (FR-AI-006): the '
            . 'safe default for "nobody decided how dangerous this is" is not '
            . '"proceed".',
            $riskClass
        ));
    }
}
