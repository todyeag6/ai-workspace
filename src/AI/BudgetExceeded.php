<?php

declare(strict_types=1);

namespace App\AI;

use RuntimeException;

/**
 * Thrown when a model call would spend more tokens or money than the request
 * itself authorised (FR-AI-002).
 *
 * WHY AN EXCEPTION AND NOT A CLAMP: silently truncating a prompt to fit a
 * budget produces a degraded answer that looks like a normal one, and the
 * caller never learns its limit was wrong. A throw stops the call BEFORE the
 * adapter is reached, so the failure costs nothing and is impossible to miss.
 *
 * Extends RuntimeException for the same reason as ReleaseGateNotMet: this is
 * one refusal, not a hierarchy, and inventing a base class for it would be
 * scaffolding without a load to carry.
 *
 * © AI WebScapes 2026
 */
final class BudgetExceeded extends RuntimeException
{
    public static function tokens(string $purpose, int $requested, int $limit): self
    {
        return new self(sprintf(
            'Refusing the model call for "%s": it needs %d prompt tokens but the '
            . 'request authorises %d. FR-AI-002 requires the token limit to be '
            . 'declared per call and honoured before the model is reached.',
            $purpose,
            $requested,
            $limit
        ));
    }

    public static function cost(string $purpose, int $estimatedCents, int $limitCents): self
    {
        return new self(sprintf(
            'Refusing the model call for "%s": its estimated cost of %d cents '
            . 'exceeds the %d cent limit the request authorises (FR-AI-002).',
            $purpose,
            $estimatedCents,
            $limitCents
        ));
    }
}
