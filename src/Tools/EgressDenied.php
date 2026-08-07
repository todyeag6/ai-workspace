<?php

declare(strict_types=1);

namespace App\Tools;

use RuntimeException;

/**
 * Thrown when a tool would send data to a destination nobody approved
 * (FR-TOOL-003).
 *
 * The allowlist here answers a different question from ToolNotAllowed. "May
 * this agent send email?" and "may this agent send email TO THAT ADDRESS?"
 * fail apart: a compromised or prompt-injected agent with a legitimate
 * send_email grant exfiltrates by choosing the recipient. Constraining the
 * destination is what turns the grant from "can talk to the internet" into
 * "can talk to these parties".
 *
 * Missing destinations are refused too. A send with no recipient is not a
 * harmless no-op to this class - it is a call whose destination the gate
 * cannot see, and an unseen destination fails closed.
 *
 * © AI WebScapes 2026
 */
final class EgressDenied extends RuntimeException
{
    public static function recipientNotApproved(string $tool, string $recipient): self
    {
        return new self(sprintf(
            'Refusing tool "%s": recipient "%s" is not on the egress '
            . 'allowlist. FR-TOOL-003 restricts outbound destinations to '
            . 'approved parties - holding a send grant is not the same as '
            . 'choosing who receives the data.',
            $tool,
            $recipient
        ));
    }

    public static function hostNotApproved(string $tool, string $host): self
    {
        return new self(sprintf(
            'Refusing tool "%s": host "%s" is not on the egress allowlist. '
            . 'The URL passed the SSRF check (it is not internal), but '
            . 'FR-TOOL-003 also requires the destination to be one we approved.',
            $tool,
            $host
        ));
    }

    public static function noTargetDeclared(string $tool): self
    {
        return new self(sprintf(
            'Refusing tool "%s": it sends data outbound but the call declared '
            . 'no recipient or URL. A destination the gate cannot see cannot '
            . 'be checked against the egress allowlist, so it fails closed.',
            $tool
        ));
    }
}
