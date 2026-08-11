<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use RuntimeException;

/**
 * The production actor behind App\SecurityAgent\ScannerAdapter. It is the
 * "sandboxed process wrapper" the adapter receives as a callable: it takes the
 * client-supplied target, validates it through TargetSanitizer (SFR-SELF-005),
 * resolves a pinned binary through the AC-002 allowlist, and spawns the tool
 * with an ARGUMENT ARRAY - never a shell string.
 *
 * WHY AN ARGUMENT ARRAY AND NOT A SHELL STRING
 * --------------------------------------------
 * Official guidance is unanimous here:
 *   - php.net proc_open manual: as of PHP 7.4 the command may be an array, in
 *     which case "the process will be opened directly (without going through a
 *     shell)". No shell means no metacharacter, no quoting, nothing to get
 *     wrong - a target containing ";" or "$()" is just one argv element.
 *   - OWASP OS Command Injection Defense: even escapeshellarg() stops OS
 *     command injection but NOT argument injection; the real defence is
 *     parameterization (an argv array) plus positive input validation - which
 *     is exactly this class plus TargetSanitizer.
 *   - CISA/FBI Secure-by-Design Alert (2024-07-10): manufacturers should ban
 *     passing a command as a single string (as opposed to an array). This repo
 *     already follows that rule in App\Infra\MysqlBinary; this class extends it
 *     to scanner targets.
 *
 * THE POSIX "--" DELIMITER
 * ------------------------
 * OWASP cites POSIX Guideline 10: the first "--" argument ends option parsing,
 * so everything after is treated as an operand even if it begins with "-".
 * Even though the target is already validated by TargetSanitizer, the delimiter
 * is appended as defense in depth: if a tool ever re-parses the argument, the
 * target can never be read as a flag.
 *
 * THE BINARY ALLOWLIST (AC-002)
 * ------------------------------
 * The tool identity the adapter declares (e.g. "nmap") is mapped to a SINGLE
 * pinned binary path from the policy. An unknown tool id is refused - the
 * platform never resolves a scanner binary from PATH, which would be a
 * supply-chain pivot. This is the scanner twin of ToolGateway's tool allowlist.
 *
 * DECIDE/ACT SPLIT KEPT INTACT
 * -----------------------------
 * This class is the ACTOR; TargetSanitizer is the DECIDER. This class performs
 * no allowlist/validation of its own beyond calling the sanitizer and reading
 * the binary allowlist - if the sanitizer is not called first, that is a
 * wiring bug, not a second policy copy that can drift. (The run() method
 * enforces the order internally, so it cannot be skipped.)
 *
 * WHY IT RETURNS A STRUCTURED ARRAY, NOT RAW STDOUT
 * --------------------------------------------------
 * ScannerAdapter::classify() trusts a structured payload (status + optional
 * data) and explicitly refuses to mine stdout for findings. This invoker
 * therefore emits JSON when it can, and otherwise returns the raw text under
 * an "output" key so the adapter records it as INFO rather than inventing a
 * finding. A scanner that prints "vulnerable!" to stdout has found nothing the
 * platform will treat as a vulnerability.
 *
 * © AI WebScapes 2026
 */
final class SafeScannerInvoker
{
    /**
     * Canonical path to the isolation policy; loaded automatically when a caller
     * constructs the invoker with only the SFR-SELF-005 policy, so the
     * SFR-SELF-001 guard is ALWAYS enforced (fail closed) and cannot be skipped
     * by omitting the argument.
     */
    private const DEFAULT_ISOLATION_POLICY = '/config/security/SCANNER_ISOLATION_POLICY.php';

    /**
     * @param array<string, mixed> $policy             The decoded SCANNER_TARGET_POLICY.php.
     * @param array<string, mixed> $isolationPolicy    The decoded SCANNER_ISOLATION_POLICY.php.
     *               Both typed loosely (config-loaded); the constructors enforce
     *               the keys they need (fail closed). When omitted, the invoker
     *               loads it from the canonical repo path so the guard runs.
     * @param IncidentSignal|null $signal              Optional audited signal emitted when a
     *               scan is refused (SFR-SELF-006). Null preserves the pure
     *               process-spawning path for callers that do not wire audit.
     *
     * @throws RuntimeException When a policy is incomplete.
     */
    public function __construct(
        private readonly array $policy,
        private readonly array $isolationPolicy = [],
        private readonly ?IncidentSignal $signal = null
    ) {
        if (!array_key_exists('tool_binaries', $policy)) {
            throw new RuntimeException(sprintf(
                'Scanner invoker policy is missing "%s"; refusing to construct an '
                . 'incomplete SFR-SELF-005 invoker (fail closed).',
                'tool_binaries'
            ));
        }
        $isolation = $this->resolveIsolationPolicy();
        if (!array_key_exists('scanner_network_name', $isolation)) {
            throw new RuntimeException(sprintf(
                'Scanner invoker isolation policy is missing "%s"; refusing to construct an '
                . 'incomplete SFR-SELF-001 guard (fail closed).',
                'scanner_network_name'
            ));
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function resolveIsolationPolicy(): array
    {
        if ($this->isolationPolicy !== []) {
            return $this->isolationPolicy;
        }
        $path = dirname(__DIR__, 2) . self::DEFAULT_ISOLATION_POLICY;
        if (!is_file($path)) {
            throw new RuntimeException(sprintf(
                'Scanner isolation policy not found at "%s"; refusing to construct an '
                . 'incomplete SFR-SELF-001 guard (fail closed).',
                $path
            ));
        }
        $loaded = require $path;
        return is_array($loaded) ? $loaded : [];
    }

    /**
     * Validates the target, resolves the pinned binary, and runs the scanner.
     *
     * @param string       $tool    The pinned tool identity (e.g. "nmap").
     * @param string       $target  A client-supplied scan target string.
     * @param list<string> $extra   Tool-controlled, platform-fixed flags
     *                              (NEVER built from the target string).
     * @return mixed The structured payload ScannerAdapter expects.
     *
     * @throws TargetRefused When the target fails SFR-SELF-005 validation.
     * @throws RuntimeException When the binary is not allowlisted or the spawn fails.
     */
    public function run(string $tool, string $target, array $extra = []): mixed
    {
        try {
            // 0. SFR-SELF-001: refuse to launch the scanner if its execution scope
            //    could reach production. The guard is fail-closed and decides before
            //    any process exists. The "reported network" is the segment the
            //    scanner claims to be on; composer/wiring supplies the real value.
            (new ScannerInfrastructureGuard($this->isolationPolicy()))
                ->assertIsolated($this->scannerNetwork(), [], $this->childEnv());

            // 1. DECIDE: refuse the target before touching a process.
            $safe = (new TargetSanitizer($this->policy))->sanitize($target);
        } catch (TargetRefused $e) {
            // SFR-SELF-006: emit an audited signal before the refusal propagates,
            // so the incident procedure has a real, measurable inbound event.
            // The decision was made by the guard; this actor only records it.
            $this->signal?->scanRefused(0, $this->reasonCode($e), 'denied', [
                'tool' => $tool,
                'guard' => 'SFR-SELF',
            ]);

            throw $e;
        }

        // 2. AC-002: resolve a pinned binary; refuse unknown tool ids.
        $binaries = $this->policy['tool_binaries'] ?? [];
        if (!is_array($binaries) || !array_key_exists($tool, $binaries)) {
            throw TargetRefused::binaryNotAllowed($tool);
        }
        $binary = $binaries[$tool];
        if (!is_string($binary) || $binary === '') {
            throw TargetRefused::binaryNotAllowed($tool);
        }

        // 3. ACT: spawn with an argv array. The target is ONE element after the
        // "--" delimiter, so it can never be parsed as a flag or a command.
        $argv = array_merge([$binary], $extra, ['--', $safe->canonical]);

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $pipes = [];
        $process = proc_open($argv, $descriptors, $pipes, null, $this->childEnv());
        if (!is_resource($process)) {
            throw new RuntimeException(sprintf('Unable to start scanner "%s" (%s).', $tool, $binary));
        }

        fclose($pipes[0]);

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);
        $stdout = is_string($stdout) ? $stdout : '';
        $stderr = is_string($stderr) ? $stderr : '';

        if ($exitCode !== 0) {
            return [
                'status' => 'error',
                'error' => trim($stderr) === '' ? sprintf('%s exited %d', $tool, $exitCode) : trim($stderr),
                'exit_code' => $exitCode,
            ];
        }

        $decoded = json_decode($stdout, true);
        if (is_array($decoded)) {
            return $decoded;
        }

        // Unstructured output is reported as output, never mined for findings.
        return ['output' => $stdout];
    }

    /**
     * A deliberately minimal environment for the child process, so the scanner
     * cannot inherit a rich host environment (and any injected env from the
     * caller never reaches it). Mirrors MysqlBinary::environment().
     *
     * @return array<string, string>
     */
    private function childEnv(): array
    {
        $path = getenv('PATH');

        return [
            'PATH' => is_string($path) && $path !== '' ? $path : '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'LC_ALL' => 'C',
        ];
    }

    /**
     * The isolation policy the SFR-SELF-001 guard consults. Resolved once at
     * construction time (loaded from the canonical path when not injected), so
     * the guard always receives a complete policy and cannot be skipped.
     *
     * @return array<string, mixed>
     */
    private function isolationPolicy(): array
    {
        return $this->resolveIsolationPolicy();
    }

    /**
     * The Docker network the scanner reports it is attached to. Sourced from the
     * isolation policy (the single source of truth for the segment name);
     * a deployment that segments correctly sets scanner_network_name to the
     * isolated network and attaches the scanner there.
     */
    private function scannerNetwork(): string
    {
        $policy = $this->resolveIsolationPolicy();
        $name = $policy['scanner_network_name'] ?? '';
        return is_string($name) ? $name : '';
    }

    /**
     * Maps a refusal to a bounded, stable reason code stored as the audit
     * object_id. The code is short and non-secret so it survives AuditLogger's
     * high-entropy redaction (SFR-AUTH-003); the full (hostile) target is never
     * recorded here.
     */
    private function reasonCode(TargetRefused $e): string
    {
        $message = $e->getMessage();
        if (str_contains($message, 'SFR-SELF-001')) {
            return 'self001:isolation';
        }
        if (str_contains($message, 'network pivoting') || str_contains($message, 'SSRF')) {
            return 'self005:network-pivot';
        }
        if (str_contains($message, 'command injection')) {
            return 'self005:cmd-injection';
        }
        if (str_contains($message, 'arbitrary tool flag')) {
            return 'self005:flag-injection';
        }
        if (str_contains($message, 'path traversal')) {
            return 'self005:path-traversal';
        }
        if (str_contains($message, 'supply-chain pivot')) {
            return 'self005:binary-not-allowed';
        }

        return 'self005:refused';
    }
}
