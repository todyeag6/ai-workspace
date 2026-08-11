<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use RuntimeException;

/**
 * Thrown when a scanner target fails SFR-SELF-005 validation.
 *
 * The target of a scan is CLIENT-SUPPLIED content - it arrives from an
 * authorized scan scope, but the string itself is attacker-influenced text
 * (a scraped hostname, a URL a tenant typed, a redirect a page returned). The
 * scanner's argv is the one place that text can become an action, so every
 * refusal here is a failure of the INPUT, caught before any process is
 * spawned.
 *
 * WHY THE MESSAGE IS SHORT AND NAMES THE REASON, NOT THE WHOLE VALUE: the
 * caller is often an automated agent whose output is itself attacker-influenced
 * (SEC-010). Echoing the full rejected target into a response is a small
 * exfiltration channel and a large hint sheet. The reason is enough for the
 * operator's log; the offending value is recorded via TargetCanonicalizer::
 * forAudit() at the call site if evidence is needed.
 *
 * © AI WebScapes 2026
 */
final class TargetRefused extends RuntimeException
{
    public static function tooLong(int $limit, int $actual): self
    {
        return new self(sprintf(
            'Refusing scan target: %d characters exceeds the %d-character ceiling '
            . '(SFR-SELF-005, path-traversal / smuggling guard).',
            $actual,
            $limit
        ));
    }

    public static function containsShellMetacharacter(string $char): self
    {
        return new self(sprintf(
            'Refusing scan target: contains shell metacharacter "%s". A target is a '
            . 'host to probe, not a command to run (SFR-SELF-005, command injection).',
            $char
        ));
    }

    public static function isInternalAddress(string $host): self
    {
        return new self(sprintf(
            'Refusing scan target: "%s" is a loopback, private, link-local or otherwise '
            . 'internal address. A client-supplied target may not aim the scanner at '
            . 'infrastructure (SFR-SELF-005, network pivoting / SSRF).',
            $host
        ));
    }

    public static function flagInjection(string $value): self
    {
        return new self(sprintf(
            'Refusing scan target: "%s" begins with "-" and would be read by the scanner '
            . 'as a tool flag rather than an operand (SFR-SELF-005, arbitrary tool flag). '
            . 'Targets are operands and are forced after the POSIX "--" delimiter.',
            $value
        ));
    }

    public static function pathTraversal(string $needle): self
    {
        return new self(sprintf(
            'Refusing scan target: contains "%s", which is a path-traversal or filesystem '
            . 'hand-off, not a web scan target (SFR-SELF-005, path traversal).',
            $needle
        ));
    }

    public static function notAnHttpTarget(string $target): self
    {
        return new self(sprintf(
            'Refusing scan target: "%s" is not an http/https URL. Scanners probe web '
            . 'surfaces only; any other scheme is out of scope (SFR-SELF-005).',
            $target
        ));
    }

    public static function binaryNotAllowed(string $tool): self
    {
        return new self(sprintf(
            'Refusing scan: tool "%s" is not on the scanner binary allowlist (AC-002). '
            . 'A scanner may only invoke pinned, version-locked binaries; an unknown tool '
            . 'id is never resolved from PATH (SFR-SELF-005 supply-chain pivot).',
            $tool
        ));
    }
}
