<?php

declare(strict_types=1);

namespace App\AI;

use InvalidArgumentException;

/**
 * Thrown when a call declares a token limit larger than the local runtime's
 * configured context window (FR-AI-001, harness compatibility).
 *
 * WHY AN EXCEPTION AND NOT A CLAMP: the runtime would either error at the
 * wire or, worse, quietly drop the head of the prompt - which returns an
 * answer reasoned from half the input while looking exactly like a good one.
 * Refusing costs one failed call; clamping costs trust in every call.
 *
 * Extends InvalidArgumentException rather than RuntimeException because the
 * fault is in the ARGUMENT the caller supplied, not in the environment: the
 * ceiling is known before anything is attempted, so this is a bad request,
 * caught before the adapter is reached.
 *
 * © AI WebScapes 2026
 */
final class ContextLimitExceeded extends InvalidArgumentException
{
    public static function overCeiling(int $requestedTokens, int $ceilingTokens): self
    {
        return new self(sprintf(
            'Refusing the model call: it declares a limit of %d tokens but the '
            . 'local runtime context window is %d (OLLAMA_CONTEXT_LENGTH). The '
            . 'limit is refused rather than clamped - a silently truncated '
            . 'prompt returns a degraded answer that reads like a sound one.',
            $requestedTokens,
            $ceilingTokens
        ));
    }
}
