<?php

declare(strict_types=1);

namespace App\Tools;

use RuntimeException;

/**
 * Thrown when an agent asks for a tool that is not in the allowlist bound to
 * that agent and agent version (FR-TOOL-001, AC-002).
 *
 * WHY THE DEFAULT ANSWER IS NO: a denylist has to be right about every tool
 * that will ever exist, including the ones added after the list was written.
 * An allowlist has to be right about the handful an agent was reviewed for.
 * Only one of those two failure modes is recoverable, so an unrecognised tool
 * name is refused rather than passed through.
 *
 * The version is part of the identity on purpose. "lead v1 may send email" is
 * a statement about a reviewed prompt and a reviewed tool set; carrying the
 * grant forward to v2 unexamined would make the release gate (FR-AGENT-002)
 * decorative.
 *
 * Extends RuntimeException for the same reason as ReleaseGateNotMet and
 * AutonomousActionRejected: one refusal, not a hierarchy.
 *
 * © AI WebScapes 2026
 */
final class ToolNotAllowed extends RuntimeException
{
    public static function notInAllowlist(string $tool, string $agent, ?string $agentVersion): self
    {
        return new self(sprintf(
            'Refusing to invoke tool "%s" for agent "%s"%s: it is not in that '
            . 'agent version\'s allowlist. AC-002 grants tools by allowlist, '
            . 'never by denylist - an unlisted tool is refused, not assumed safe.',
            $tool,
            $agent,
            $agentVersion === null ? '' : ' version ' . $agentVersion
        ));
    }

    public static function agentOutOfScope(string $tool, string $requested, string $bound): self
    {
        return new self(sprintf(
            'Refusing to invoke tool "%s" for agent "%s": this gateway carries '
            . 'the allowlist of agent "%s". A grant belongs to the agent it was '
            . 'reviewed for and does not transfer at call time.',
            $tool,
            $requested,
            $bound
        ));
    }
}
