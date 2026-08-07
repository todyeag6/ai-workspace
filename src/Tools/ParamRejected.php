<?php

declare(strict_types=1);

namespace App\Tools;

use RuntimeException;

/**
 * Thrown when a tool parameter fails server-side validation (FR-TOOL-002).
 *
 * The parameter that matters most is a URL. A model that can name the target
 * of an HTTP call can name http://169.254.169.254/ and read the cloud
 * instance credentials, or http://127.0.0.1:6379/ and speak to Redis. That is
 * SSRF with the model as the confused deputy, and the only reliable place to
 * stop it is here - server side, before the connector ever sees the value.
 *
 * WHY THE MESSAGE NAMES THE REASON BUT NOT MUCH ELSE: the caller is often an
 * agent whose output is attacker-influenced text (SEC-010). Echoing the full
 * rejected value into a response is a small exfiltration channel and a large
 * hint sheet; the value is named for the operator's log, the reason is short.
 *
 * © AI WebScapes 2026
 */
final class ParamRejected extends RuntimeException
{
    public static function malformedUrl(string $param, string $value): self
    {
        return new self(sprintf(
            'Refusing tool call: parameter "%s" is not a valid absolute URL '
            . '("%s"). FR-TOOL-002 validates parameters server side; a value '
            . 'the validator cannot parse is refused, not guessed at.',
            $param,
            $value
        ));
    }

    public static function schemeNotAllowed(string $param, string $scheme): self
    {
        return new self(sprintf(
            'Refusing tool call: parameter "%s" uses scheme "%s". Only http '
            . 'and https are allowed - file, gopher, dict and friends exist in '
            . 'SSRF payloads for a reason.',
            $param,
            $scheme
        ));
    }

    public static function blockedTarget(string $param, string $host): self
    {
        return new self(sprintf(
            'Refusing tool call: parameter "%s" points at "%s", which is a '
            . 'loopback, private, link-local or otherwise internal target. '
            . 'FR-TOOL-002 blocks server-side requests to infrastructure the '
            . 'caller should not be able to reach through us (SSRF, including '
            . 'the 169.254.169.254 cloud metadata endpoint).',
            $param,
            $host
        ));
    }

    public static function notAString(string $param, string $type): self
    {
        return new self(sprintf(
            'Refusing tool call: parameter "%s" must be a string URL, got %s. '
            . 'An array or object here is a parser-confusion attempt, not a '
            . 'target.',
            $param,
            $type
        ));
    }
}
