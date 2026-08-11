<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use InvalidArgumentException;

/**
 * The SFR-SELF-005 gate: turns a client-supplied scan target string into a
 * validated operand, or refuses it.
 *
 * WHAT THIS IS, AND DELIBERATELY IS NOT
 * --------------------------------------
 * It DECIDES. It does not spawn anything, resolve DNS, or open a socket - the
 * same DECIDE/ACT split App\Tools\ToolGateway and App\AI\AIGateway use. The
 * thing that touches the network is App\SecurityAgent\SafeScannerInvoker, which
 * calls this first and only then builds an argv array. Keep the validator pure
 * so every refusal path is provable without a process or a network.
 *
 * WHY IT COMPOSES WITH TargetCanonicalizer RATHER THAN REPLACING IT
 * -------------------------------------------------------------------
 * TargetCanonicalizer (SFR-AUTH-002) lowercases, drops the fragment, refuses
 * non-http schemes and userinfo. It does NOT refuse internal addresses
 * (169.254.169.254 canonicalizes fine) and it does NOT refuse shell
 * metacharacters or flag injection living in the host. So the ordering here is:
 * canonicalize FIRST (so we compare a normalised, unambiguous string and so
 * that non-http schemes / userinfo are already refused), THEN apply the
 * SFR-SELF-005-specific refusals on the canonical form.
 *
 * WHY THE SHELL-METACHARACTER CHECK IS ON THE HOST, NOT THE WHOLE URL
 * -------------------------------------------------------------------
 * A legitimate web target carries shell metacharacters in its QUERY string
 * (e.g. "https://app.client.test/?a=1&b=2" contains "&"). Refusing those would
 * break ordinary scanning. A HOST, by contrast, is only ever [a-z0-9.-] (plus
 * brackets for an IPv6 literal); any shell metacharacter in the host is a
 * hostile attempt, never a legitimate name. So metacharacters are refused only
 * where they can mean something bad - the host - and the argv-array invoker
 * neutralises them everywhere else as defense in depth.
 *
 * ORDER OF REFUSALS, AND WHY
 * ---------------------------
 *   1. length      - cheapest, and bounds every later parse.
 *   2. canonicalize (SFR-AUTH-002) - refuses non-http schemes, userinfo,
 *                    empty host. Throws InvalidArgumentException on malformed
 *                    input, which we re-throw as TargetRefused.
 *   3. path        - traversal / filesystem hand-off substrings in the path.
 *   4. host meta   - shell / command-separator chars in the host: impossible
 *                    in a real hostname, therefore hostile.
 *   5. address     - network pivot: the host resolves to a blocked internal/
 *                    loopback/link-local range. Pure, DNS-free (see below).
 *   6. flag        - the host must not begin with "-": that would let a target
 *                    become a tool FLAG rather than an operand (arbitrary tool
 *                    flags). The invoker also appends a POSIX "--" delimiter as
 *                    defense in depth, but the gate refuses regardless.
 *
 * WHY THE ADDRESS CHECK NEVER RESOLVES A NAME
 * ------------------------------------------
 * Calling gethostbyname()/dns_get_record() during validation would itself be
 * an outbound request driven by attacker-supplied input (mirrors the stated
 * limit in ToolGateway and TargetCanonicalizer): a lookup of an internal name
 * leaks it to whatever resolver answers, and the lookup is a side effect a
 * validator is not entitled to have. So the check is pure: host literals are
 * matched against the policy's blocked CIDRs, and hostnames against the
 * internal-name lists. Two honest limits, documented not hidden:
 *   - DNS rebinding and a public name whose A record points at 10.0.0.5 are NOT
 *     caught here. That belongs to resolve-then-pin at connection time, which
 *     is the invoker's job (it holds the socket), not the validator's.
 *   - An attacker who controls DNS can return a public address at validation
 *     time and the internal one at scan time; the network-layer egress control
 *     on the sandbox is the real backstop for that, and it lives outside this
 *     repo's validator by design.
 *
 * © AI WebScapes 2026
 */
final class TargetSanitizer
{
    /**
     * @param array<string, mixed> $policy The decoded SCANNER_TARGET_POLICY.php.
     *               Typed loosely because it is config-loaded; the constructor
     *               enforces the keys it needs (fail closed), so a missing key
     *               is a construction error, not a silent default.
     *
     * @throws \InvalidArgumentException When the policy is missing a required key.
     */
    public function __construct(private readonly array $policy)
    {
        $required = ['blocked_v4_cidrs', 'blocked_internal_hosts', 'blocked_internal_host_suffixes', 'forbidden_path_substrings', 'forbidden_shell_metacharacters', 'max_target_length'];
        foreach ($required as $key) {
            if (!array_key_exists($key, $policy)) {
                throw new \InvalidArgumentException(sprintf(
                    'Scanner target policy is missing "%s"; refusing to construct an '
                    . 'incomplete SFR-SELF-005 guard (fail closed).',
                    $key
                ));
            }
        }
    }

    /**
     * Validates the target and returns a SanitizedTarget on success, or throws
     * TargetRefused.
     *
     * @throws TargetRefused
     */
    public function sanitize(string $target): SanitizedTarget
    {
        $limit = (int) $this->policy['max_target_length'];
        $length = mb_strlen($target, '8bit');
        if ($length > $limit) {
            throw TargetRefused::tooLong($limit, $length);
        }

        // Canonicalize (SFR-AUTH-002): refuses non-http schemes, userinfo,
        // empty host. Throws InvalidArgumentException on malformed input.
        try {
            $canonical = TargetCanonicalizer::canonicalize($target);
        } catch (InvalidArgumentException $e) {
            throw TargetRefused::notAnHttpTarget($target);
        }

        // Extract the host with a regex because parse_url mis-parses an IPv6
        // literal once TargetCanonicalizer has stripped its brackets (it reads
        // "::1" as host ":" port 1, so the IP check would never fire). The
        // shape is fixed by the canonicalizer: scheme://host[...][/path].
        if (preg_match('~^https?://([^/?#]+)~i', $canonical, $m) !== 1) {
            throw TargetRefused::notAnHttpTarget($target);
        }
        $hostWithPort = strtolower((string) $m[1]);
        // Strip an optional port. The canonicalizer keeps a default port only
        // when it differs from 80/443, so an IPv4 or named host may carry
        // ":6379". Strip the port only when it follows a "." (IPv4/name) or a
        // "]" (IPv6 was bracketed before canonicalization): a bare IPv6 like
        // "::1" must keep its colons, so a naive "/:\d+$/" would wrongly turn
        // "::1" into ":" and let the loopback slip through.
        $host = preg_replace('/([\w.-]+|\[[0-9a-fA-F:]+])(:\d+)$/', '$1', $hostWithPort);
        if (!is_string($host)) {
            throw TargetRefused::notAnHttpTarget($target);
        }
        // The path is everything after the host; empty when the URL has none.
        $path = (string) substr($canonical, strlen('https://') + strlen($hostWithPort));

        // Path-traversal / filesystem hand-off, checked on the canonical path.
        // (Non-http schemes and userinfo were already refused by the
        // canonicalizer, so a scheme/prefix hand-off cannot reach here.)
        foreach ($this->policy['forbidden_path_substrings'] as $needle) {
            if (is_string($needle) && str_contains($path, $needle)) {
                throw TargetRefused::pathTraversal($needle);
            }
        }

        // Shell / command-separator metacharacters in the HOST only. A real
        // hostname is [a-z0-9.-] (plus [] for IPv6), so any of these is a
        // hostile attempt, never a legitimate name. Query strings may contain
        // them and are left alone (and are inert under the argv-array invoker).
        foreach ($this->policy['forbidden_shell_metacharacters'] as $char) {
            if (is_string($char) && str_contains($host, $char)) {
                throw TargetRefused::containsShellMetacharacter($char);
            }
        }

        // Network pivot: refuse internal / loopback / link-local destinations.
        if ($this->isInternalHost($host)) {
            throw TargetRefused::isInternalAddress($host);
        }

        // Arbitrary tool flag: the host must not be parsed as a flag. The
        // canonical host is always a hostname, so the flag check is really
        // about a degenerate canonicalization, but we assert it to be safe.
        if (str_starts_with($host, '-')) {
            throw TargetRefused::flagInjection($host);
        }

        return new SanitizedTarget($canonical, $host);
    }

    /**
     * Pure, DNS-free internal-address check (see class docblock).
     */
    private function isInternalHost(string $host): bool
    {
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return $this->isBlockedIpv4($host);
        }

        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return $this->isBlockedIpv6($host);
        }

        if (preg_match('/^[0-9.]+$/', $host) === 1) {
            // Integer/dotted decimal forms that are not valid hostnames.
            return true;
        }

        if (in_array($host, $this->policy['blocked_internal_hosts'], true)) {
            return true;
        }

        foreach ($this->policy['blocked_internal_host_suffixes'] as $suffix) {
            if (is_string($suffix) && str_ends_with($host, $suffix)) {
                return true;
            }
        }

        return false;
    }

    private function isBlockedIpv4(string $ip): bool
    {
        $address = ip2long($ip);
        if ($address === false) {
            return true;
        }

        foreach ($this->policy['blocked_v4_cidrs'] as $cidr) {
            if (!is_string($cidr) || !str_contains($cidr, '/')) {
                continue;
            }
            [$network, $bits] = explode('/', $cidr, 2);
            $networkLong = ip2long($network);
            if ($networkLong === false) {
                continue;
            }
            $mask = -1 << (32 - (int) $bits);
            if (($address & $mask) === ($networkLong & $mask)) {
                return true;
            }
        }

        return false;
    }

    private function isBlockedIpv6(string $ip): bool
    {
        $packed = @inet_pton($ip);
        if ($packed === false || strlen($packed) !== 16) {
            return true;
        }

        $hex = bin2hex($packed);

        // ::ffff:10.0.0.1 - an IPv4 address wearing a v6 hat.
        if (str_starts_with($hex, '00000000000000000000ffff')) {
            $octets = [];
            foreach ([24, 26, 28, 30] as $offset) {
                $octets[] = (string) hexdec(substr($hex, $offset, 2));
            }

            return $this->isBlockedIpv4(implode('.', $octets));
        }

        // ::1 (loopback) and :: (unspecified).
        if ($hex === str_repeat('0', 31) . '1' || $hex === str_repeat('0', 32)) {
            return true;
        }

        $firstByte = (int) hexdec(substr($hex, 0, 2));
        $secondByte = (int) hexdec(substr($hex, 2, 2));

        // fc00::/7 unique-local, fe80::/10 link-local (the v6 metadata route).
        return ($firstByte & 0xFE) === 0xFC
            || ($firstByte === 0xFE && ($secondByte & 0xC0) === 0x80);
    }
}
