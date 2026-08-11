<?php

/**
 * SFR-SELF-005 - scanner target safety policy.
 *
 * SOURCE OF THE REQUIREMENT
 * --------------------------
 * FRD section 6, SFR-SELF-005 [Must]: "The platform shall prevent
 * client-supplied content from causing command injection, arbitrary tool
 * flags, path traversal, or network pivoting."
 *
 * WHY THESE NUMBERS/STRINGS LIVE HERE
 * ------------------------------------
 * As with config/security/FINDING_SLA.php and the other ratifiable policy
 * files, the approved baseline sets NO specific blocked ranges, host names or
 * length ceilings. Those are policy decisions, not code, and they are kept in
 * this single auditable, change-controlled file so a ratifier edits the policy
 * without touching the engine. SFR-SELF-005's runtime guard
 * (App\SecurityAgent\TargetSanitizer) reads this file; if a number here is
 * wrong, the fix is here, not in the class.
 *
 * THE GUARD IS FAIL-CLOSED: a missing key or an unreadable file means the
 * policy object refuses to construct, and the scanner does not run. Nothing in
 * the baseline says "refuse more loosely when the policy is thin", so the
 * default is the opposite.
 *
 * EXTERNAL GROUNDING (reviewed 2026-08-11)
 * ----------------------------------------
 * The blocked CIDR list and the internal-host list are reused from the
 * network-pivot defence already shipped in App\Tools\ToolGateway
 * (FR-TOOL-002/003, AC-002), because SFR-SELF-005's "network pivoting" clause
 * is the scanner-side twin of that gate - a scanner pointed at
 * 169.254.169.254 must be refused for the same reasons a tool call to it is.
 * The CIDRs are the special-use / internal ranges:
 *   0.0.0.0/8, 10/8, 100.64/10 (CGNAT/Tailscale), 127/8, 169.254/16 (cloud
 *   metadata), 172.16/12, 192.168/16, 192.0.0/24, 198.18/15 (benchmarking),
 *   224/4 and 240/4 (multicast / reserved). Loopback v6 (::1) and ULA
 * (fc00::/7) are added at validation time; they are not CIDR strings.
 *
 * The argument-injection and command-injection rules follow the OWASP OS
 * Command Injection Defense Cheat Sheet (Parameterization + positive
 * allowlist input validation; POSIX Guideline 10 `--` delimiter ends option
 * parsing) and the CISA/FBI Secure-by-Design Alert of 2024-07-10, which tells
 * manufacturers to BAN passing a command as a single string (as opposed to an
 * array) at pull-request time. This repo's own App\Infra\MysqlBinary already
 * follows that rule - the scanner invoker extends it to scanner targets.
 *
 * STATUS: PROPOSED. Owner to ratify (flip this header to RATIFIED). Until then
 * the pinning test
 * tests/SecurityAgent/ScannerTargetSafetyTest.php::
 * test_shipped_scanner_target_policy_pins_its_contract_terms stays RED on the
 * PROPOSED state and pins the specific values once ratified, so an unsourced
 * edit fails CI.
 *
 * @return array{
 *     blocked_v4_cidrs: list<string>,
 *     blocked_internal_hosts: list<string>,
 *     blocked_internal_host_suffixes: list<string>,
 *     forbidden_path_substrings: list<string>,
 *     forbidden_shell_metacharacters: list<string>,
 *     max_target_length: int,
 *     tool_binaries: array<string, string>,
 *     status: string
 * }
 */

declare(strict_types=1);

return [
    // Ranges a scanner must never be aimed at - they are infrastructure, not
    // a client's web surface. Reused from ToolGateway (FR-TOOL-003).
    'blocked_v4_cidrs' => [
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
    ],

    // Hosts that are internal by definition - never a legitimate scan target.
    'blocked_internal_hosts' => [
        'localhost',
        'metadata',
        'metadata.google.internal',
        'ip6-localhost',
        'ip6-loopback',
    ],

    // Suffixes that denote an internal / private name.
    'blocked_internal_host_suffixes' => [
        '.localhost',
        '.local',
        '.internal',
        '.compute.internal',
        '.home.arpa',
    ],

    // Path components that betray a path-traversal or absolute-path attempt.
    // These are refused regardless of the host, because a target like
    // https://app.client.test/../../etc/passwd or ...:///etc/passwd is not a
    // web scan, it is an attempt to reach the filesystem.
    'forbidden_path_substrings' => [
        '..',            // directory ascent
        '/etc/',         // absolute system paths (Unix)
        '\\windows\\',   // absolute system paths (Windows, backslash)
        'c:\\',          // drive-rooted path (Windows)
        'file://',       // scheme hand-off to the local filesystem
        'gopher://',     // off-protocol pivots
        'dict://',
    ],

    // Characters that, anywhere in a target string, mean "this is not a target,
    // it is an attempt to break out into a command or a second argument."
    // The argv-array invoker already removes shell semantics, but a target
    // carrying these is refused BEFORE it ever reaches argv, so the refusal
    // does not depend on the downstream executor being perfect.
    'forbidden_shell_metacharacters' => [
        ';',   // command separator
        '|',   // pipe
        '&',   // background / command separator
        '$',   // variable / command substitution opener
        '`',   // backtick command substitution
        '>',   // output redirection
        '<',   // input redirection
        "\n",  // newline (multi-command)
        "\r",
    ],

    // A target longer than this is not a target; it is a smuggling attempt.
    // 2048 covers the longest realistic URL with query and many path segments.
    'max_target_length' => 2048,

    // AC-002 allowlist: the ONLY binaries a scanner adapter may invoke, keyed
    // by the pinned tool identity the adapter declares. An unknown tool id is
    // refused - the platform never resolves a scanner binary by any name the
    // caller supplies. This is the scanner analogue of ToolGateway's tool
    // allowlist; it is the check that makes the argv list bounded.
    'tool_binaries' => [
        // Example shape - the deployment pins real, version-locked binaries.
        // Left as an explicit, change-controlled mapping (not auto-discovered
        // from PATH, which would be a supply-chain pivot).
        'nmap'     => '/usr/bin/nmap',
        'nuclei'   => '/usr/bin/nuclei',
        'tls-probe' => '/usr/bin/tls-probe',
    ],

    // Flip to 'RATIFIED' once the owner approves the values above.
    'status' => 'PROPOSED',
];
