<?php

declare(strict_types=1);

namespace App\Tools;

use App\AI\ActionAuthority;

/**
 * The single gate every tool call passes through (FR-TOOL-001/002/003,
 * AC-002, FR-AI-006).
 *
 * WHAT THIS CLASS DOES AND DELIBERATELY DOES NOT DO
 * -------------------------------------------------
 * It decides. It does not act. invoke() returns a deterministic "allowed"
 * record and performs no send, no fetch and no delete, mirroring the AC-003
 * split already used for AIGateway: the component that judges must not be the
 * component that can be talked into acting. Effectors are wired in later
 * phases and call this gate first.
 *
 * ORDER OF CHECKS, AND WHY IT IS THIS ORDER
 * -----------------------------------------
 *   1. allowlist   - cheapest, and it is the check that makes the rest
 *                    bounded: a tool nobody granted never reaches parameter
 *                    parsing, so parser bugs are not reachable by unlisted
 *                    tool names.
 *   2. parameters  - SSRF. Runs before egress because "is this target
 *                    internal infrastructure?" must not be answerable by
 *                    putting the internal host on the egress allowlist.
 *   3. egress      - approved destinations only.
 *   4. authority   - FR-AI-006 last, immediately before the (stubbed) effect,
 *                    so a high-impact call that would fail an earlier check
 *                    is refused for the accurate reason.
 *
 * WHY THE URL CHECK NEVER RESOLVES A NAME
 * ---------------------------------------
 * Calling gethostbyname()/dns_get_record() during validation would itself be
 * an outbound request driven by attacker-supplied input: a DNS lookup of an
 * internal name leaks it to whatever resolver answers, and the lookup is a
 * side effect a validator is not entitled to have. So the check is pure: IP
 * literals are matched against hardcoded blocked CIDRs, and hostnames are
 * matched against internal-name patterns.
 *
 * STATED LIMIT: this therefore does NOT stop DNS rebinding, nor a public name
 * whose A record points at 10.0.0.5. Closing that needs resolve-then-pin at
 * connection time, which belongs to the HTTP effector (it is the only thing
 * holding the socket), not to a validator. Documented rather than hidden.
 *
 * © AI WebScapes 2026
 */
final class ToolGateway
{
    /**
     * Parameter names carrying a target URL. Exact names plus suffixes, so
     * callback_url and metrics_endpoint are covered without a denylist of
     * everything else.
     *
     * @var list<string>
     */
    private const URL_PARAM_NAMES = ['url', 'endpoint', 'uri', 'target'];

    /** @var list<string> */
    private const URL_PARAM_SUFFIXES = ['_url', '_endpoint', '_uri'];

    /** @var list<string> */
    private const ALLOWED_SCHEMES = ['http', 'https'];

    /**
     * Ranges no server-side fetch may reach. 169.254.0.0/16 covers the
     * 169.254.169.254 metadata endpoint of AWS, Azure and DigitalOcean;
     * 100.64/10 is carrier NAT (and Tailscale); 192.0.0/24, 198.18/15,
     * 224/4 and 240/4 are special-use space with no legitimate fetch target.
     *
     * @var list<string>
     */
    private const BLOCKED_V4_CIDRS = [
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.0.0.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '224.0.0.0/4',
        '240.0.0.0/4',
    ];

    /**
     * Hostnames that are internal by name. Not a denylist standing in for the
     * allowlist: the allowlist that decides whether a call happens at all is
     * the tool allowlist plus the egress allowlist. This list only refuses
     * names that are internal by definition and could never be an approved
     * public destination.
     *
     * @var list<string>
     */
    private const INTERNAL_HOSTS = ['localhost', 'metadata', 'metadata.google.internal'];

    /** @var list<string> */
    private const INTERNAL_HOST_SUFFIXES = [
        '.localhost',
        '.local',
        '.internal',
        '.compute.internal',
        '.home.arpa',
    ];

    /**
     * Tools whose whole purpose is to move data off this machine.
     *
     * @var list<string>
     */
    private const EGRESS_TOOLS = ['send_email', 'http_fetch', 'webhook'];

    /**
     * Parameters naming a human recipient rather than a host.
     *
     * @var list<string>
     */
    private const RECIPIENT_PARAMS = ['recipient', 'to', 'email'];

    /**
     * Risk class per tool, mirroring the seed rows in
     * migrations/003_tools.sql. Kept in PHP as well as SQL because the gate
     * must be able to refuse before it has a database connection, and because
     * a tool nobody classified must not be classified BY the caller.
     *
     * @var array<string, string>
     */
    private const DEFAULT_RISK_CLASSES = [
        'send_email' => 'medium',
        'http_fetch' => 'low',
        'webhook' => 'medium',
        'crm_lookup' => 'low',
        'calendar_read' => 'low',
        'refund' => 'high',
        'delete_db' => 'critical',
        'wire_transfer' => 'critical',
        'contract_sign' => 'critical',
    ];

    /** @var list<string> */
    private const HIGH_IMPACT_CLASSES = ['high', 'critical'];

    /**
     * @param list<string>          $allowed         Tools this agent version may call.
     * @param list<string>          $egressAllowlist Approved recipients ('ops@x.test',
     *                                               '@x.test' for a whole domain) and
     *                                               hosts ('api.x.test', '.x.test' for a
     *                                               whole zone).
     * @param array<string, string> $riskClasses     Tool to risk class. Anything absent
     *                                               is treated as high (fail closed).
     */
    public function __construct(
        private readonly array $allowed,
        private readonly string $agent,
        private readonly ?string $agentVersion = null,
        private readonly ?ActionAuthority $auth = null,
        private readonly array $egressAllowlist = [],
        private readonly array $riskClasses = self::DEFAULT_RISK_CLASSES,
    ) {
    }

    /**
     * Runs every gate and returns the decision record.
     *
     * @param array<string, mixed> $params
     *
     * @return array{
     *     tool: string,
     *     agent: string,
     *     agent_version: string|null,
     *     status: string,
     *     params: array<string, mixed>
     * }
     *
     * @throws ToolNotAllowed                          Tool outside this agent version's allowlist.
     * @throws ParamRejected                           A parameter failed validation (SSRF).
     * @throws EgressDenied                            Destination outside the egress allowlist.
     * @throws \App\AI\AutonomousActionRejected        High-impact tool with no human decision.
     */
    public function invoke(string $tool, string $agent, array $params): mixed
    {
        $this->assertAllowlisted($tool, $agent);
        $this->assertParamsValid($params);
        $this->assertEgressApproved($tool, $params);
        $this->assertAuthorised($tool, $params);

        // GATE ONLY - no send, no fetch, no delete. See the class docblock.
        return [
            'tool' => $tool,
            'agent' => $agent,
            'agent_version' => $this->agentVersion,
            'status' => 'allowed',
            'params' => $params,
        ];
    }

    /**
     * AC-002. The grant belongs to one agent and one version of it.
     */
    private function assertAllowlisted(string $tool, string $agent): void
    {
        if ($agent !== $this->agent) {
            throw ToolNotAllowed::agentOutOfScope($tool, $agent, $this->agent);
        }

        if (!in_array($tool, $this->allowed, true)) {
            throw ToolNotAllowed::notInAllowlist($tool, $agent, $this->agentVersion);
        }
    }

    /**
     * FR-TOOL-002. Every URL-shaped parameter, whoever supplied it.
     *
     * @param array<string, mixed> $params
     */
    private function assertParamsValid(array $params): void
    {
        foreach ($params as $name => $value) {
            if (!$this->isUrlParam($name)) {
                continue;
            }

            if (!is_string($value)) {
                throw ParamRejected::notAString($name, get_debug_type($value));
            }

            $this->assertUrlSafe($name, $value);
        }
    }

    private function isUrlParam(string $name): bool
    {
        $lower = strtolower($name);
        if (in_array($lower, self::URL_PARAM_NAMES, true)) {
            return true;
        }

        foreach (self::URL_PARAM_SUFFIXES as $suffix) {
            if (str_ends_with($lower, $suffix)) {
                return true;
            }
        }

        return false;
    }

    private function assertUrlSafe(string $param, string $url): void
    {
        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw ParamRejected::malformedUrl($param, $url);
        }

        $parts = parse_url($url);
        if (!is_array($parts)) {
            throw ParamRejected::malformedUrl($param, $url);
        }

        $scheme = isset($parts['scheme']) ? strtolower((string) $parts['scheme']) : '';
        if (!in_array($scheme, self::ALLOWED_SCHEMES, true)) {
            throw ParamRejected::schemeNotAllowed($param, $scheme === '' ? '(none)' : $scheme);
        }

        // Credentials in a URL are a parser-confusion classic
        // (http://approved.example.com@169.254.169.254/): different libraries
        // disagree about which side is the host. Refuse the ambiguity.
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw ParamRejected::blockedTarget($param, 'userinfo@host');
        }

        $host = $this->hostOf($parts);
        if ($host === '') {
            throw ParamRejected::malformedUrl($param, $url);
        }

        if ($this->isBlockedHost($host)) {
            throw ParamRejected::blockedTarget($param, $host);
        }
    }

    /**
     * @param array<string, mixed> $parts Output of parse_url().
     */
    private function hostOf(array $parts): string
    {
        $host = $parts['host'] ?? '';
        if (!is_string($host)) {
            return '';
        }

        // parse_url keeps the brackets on an IPv6 literal.
        return strtolower(trim($host, '[]'));
    }

    /**
     * Pure, DNS-free. See the class docblock for the rebinding caveat.
     */
    private function isBlockedHost(string $host): bool
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return $this->isBlockedIp($host);
        }

        // Decimal/octal/hex integer forms of an IPv4 address (2130706433,
        // 0177.0.0.1) are not valid hostnames but several HTTP clients accept
        // them. Anything that is not a plain dotted name is refused.
        if (preg_match('/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$/', $host) !== 1) {
            return true;
        }

        if (preg_match('/^[0-9.]+$/', $host) === 1) {
            return true;
        }

        if (in_array($host, self::INTERNAL_HOSTS, true)) {
            return true;
        }

        foreach (self::INTERNAL_HOST_SUFFIXES as $suffix) {
            if (str_ends_with($host, $suffix)) {
                return true;
            }
        }

        return false;
    }

    private function isBlockedIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return $this->isBlockedIpv4($ip);
        }

        return $this->isBlockedIpv6($ip);
    }

    private function isBlockedIpv4(string $ip): bool
    {
        $address = ip2long($ip);
        if ($address === false) {
            return true;
        }

        foreach (self::BLOCKED_V4_CIDRS as $cidr) {
            [$network, $bits] = explode('/', $cidr, 2);
            $networkLong = ip2long($network);
            if ($networkLong === false) {
                return true;
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

        // ::ffff:10.0.0.1 and friends - an IPv4 address wearing a v6 hat.
        // Rebuilt octet by octet rather than through long2ip(): the last four
        // bytes ARE the address, and no integer round-trip can misread them.
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

    /**
     * FR-TOOL-003. Approved destinations only, and no destination is not a
     * pass.
     *
     * @param array<string, mixed> $params
     */
    private function assertEgressApproved(string $tool, array $params): void
    {
        if (!in_array($tool, self::EGRESS_TOOLS, true)) {
            return;
        }

        $checked = false;

        foreach ($params as $name => $value) {
            if (!is_string($value)) {
                continue;
            }

            if (in_array(strtolower($name), self::RECIPIENT_PARAMS, true)) {
                $checked = true;
                if (!$this->isApprovedRecipient($value)) {
                    throw EgressDenied::recipientNotApproved($tool, $value);
                }
                continue;
            }

            if ($this->isUrlParam($name)) {
                $checked = true;
                $parts = parse_url($value);
                $host = is_array($parts) ? $this->hostOf($parts) : '';
                if (!$this->isApprovedHost($host)) {
                    throw EgressDenied::hostNotApproved($tool, $host === '' ? $value : $host);
                }
            }
        }

        if (!$checked) {
            throw EgressDenied::noTargetDeclared($tool);
        }
    }

    private function isApprovedRecipient(string $recipient): bool
    {
        $needle = strtolower(trim($recipient));

        foreach ($this->egressAllowlist as $entry) {
            $approved = strtolower(trim($entry));
            if ($approved === $needle) {
                return true;
            }

            // '@aiwebscapes.test' approves a whole mail domain.
            if (str_starts_with($approved, '@') && str_ends_with($needle, $approved)) {
                return true;
            }
        }

        return false;
    }

    private function isApprovedHost(string $host): bool
    {
        if ($host === '') {
            return false;
        }

        foreach ($this->egressAllowlist as $entry) {
            $approved = strtolower(trim($entry));
            if ($approved === $host) {
                return true;
            }

            // '.aiwebscapes.test' approves the zone, and the leading dot stops
            // 'evil-aiwebscapes.test' from matching by suffix.
            if (str_starts_with($approved, '.') && str_ends_with($host, $approved)) {
                return true;
            }
        }

        return false;
    }

    /**
     * FR-AI-006. A high-impact tool is routed to ActionAuthority, which
     * refuses: no autonomous system signs off money movement or destruction.
     *
     * Two fail-closed choices worth naming. An unclassified tool is treated as
     * high, because "nobody wrote down how dangerous this is" is not evidence
     * that it is safe. And when no ActionAuthority was injected the gate
     * builds one rather than skipping the check - omitting the collaborator
     * must not be a way to obtain permission.
     *
     * @param array<string, mixed> $params
     */
    private function assertAuthorised(string $tool, array $params): void
    {
        $riskClass = strtolower($this->riskClasses[$tool] ?? 'high');

        if (!in_array($riskClass, self::HIGH_IMPACT_CLASSES, true)) {
            return;
        }

        ($this->auth ?? new ActionAuthority())->authorizeTransaction($params, $riskClass);
    }
}
