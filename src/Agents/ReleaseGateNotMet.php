<?php

declare(strict_types=1);

namespace App\Agents;

use RuntimeException;

/**
 * Thrown when an agent activation is attempted without the release gates
 * having reported success (FR-AGENT-002).
 *
 * WHY AN EXCEPTION AND NOT A false RETURN: a boolean return is ignorable, and
 * the failure mode of ignoring it is "an ungated agent is live in a client
 * tenant". A throw cannot be ignored by accident, and it stops the caller
 * before any write happens, which is what keeps the status column truthful.
 *
 * Extends RuntimeException rather than a domain base class: there is exactly
 * one agent-domain refusal so far, and inventing a hierarchy for it would be
 * scaffolding without a load to carry.
 *
 * © AI WebScapes 2026
 */
final class ReleaseGateNotMet extends RuntimeException
{
    public static function gatesNotPassed(int $agentId): self
    {
        return new self(sprintf(
            'Refusing to activate agent %d: the release gate has not passed. '
            . 'FR-AGENT-002 requires an agent to stay disabled until security '
            . 'review, evaluation and owner sign-off report success.',
            $agentId
        ));
    }

    public static function retired(int $agentId, ?string $retirementDate): self
    {
        return new self(sprintf(
            'Refusing to activate agent %d: it was retired%s. A retired agent '
            . 'passes no release gate - register a new agent instead of '
            . 'resurrecting a decommissioned one.',
            $agentId,
            $retirementDate === null ? '' : ' on ' . $retirementDate
        ));
    }
}
