<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use RuntimeException;

/**
 * Raised when an authorization missing a mandatory element is asked to become
 * active (SFR-AUTH-001, SBR-3.1).
 *
 * SBR-3.1 lists what must be RECORDED before a scan starts: client
 * authorization, in-scope assets, allowed techniques, timing, contacts and
 * stop conditions. Activating a record that is missing any of them would
 * create an "active" authorization that the per-request gate then has to
 * refuse anyway - so the refusal is moved forward to the transition, where the
 * gap is fixable, instead of surfacing later as an unexplained scan failure.
 *
 * © AI WebScapes 2026
 */
final class IncompleteAuthorization extends RuntimeException
{
    public static function forId(int $authorizationId): self
    {
        return new self(sprintf(
            'Authorization %d is incomplete: an active authorization requires a client name, a '
            . 'technique profile, a validity period (both bounds, start before end) and a stop '
            . 'contact before scheduling (SFR-AUTH-001, SBR-3.1).',
            $authorizationId
        ));
    }
}
