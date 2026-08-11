<?php

declare(strict_types=1);

namespace App\Tests\SecurityAgent;

use App\SecurityAgent\SafeScannerInvoker;
use App\SecurityAgent\ScannerAdapter;
use App\SecurityAgent\ScannerResult;
use App\SecurityAgent\TargetRefused;
use App\SecurityAgent\TargetSanitizer;
use App\Tests\TestCase;
use InvalidArgumentException;
use RuntimeException;

/**
 * SFR-SELF-005 - the platform shall prevent client-supplied content from
 * causing command injection, arbitrary tool flags, path traversal, or network
 * pivoting.
 *
 * The guard is App\SecurityAgent\TargetSanitizer (pure, decide-not-act) composed
 * with App\SecurityAgent\SafeScannerInvoker (the actor that spawns the scanner
 * through an argv ARRAY, never a shell string). The invoker is the production
 * executor handed to ScannerAdapter, so the hostile target string is caught
 * BEFORE it can become an argv element or a process.
 *
 * Each refusal clause has its own test, and the falsification probes (run by
 * the harness, not here) confirm that disabling a clause lets the matching
 * hostile target through - i.e. the green tests below are not accidentally
 * passing.
 *
 * © AI WebScapes 2026
 */
final class ScannerTargetSafetyTest extends TestCase
{
    /**
     * @return array<string, mixed>
     */
    private function policy(): array
    {
        $raw = require dirname(__DIR__, 2) . '/config/security/SCANNER_TARGET_POLICY.php';

        return is_array($raw) ? $raw : [];
    }

    private function sanitizer(): TargetSanitizer
    {
        return new TargetSanitizer($this->policy());
    }

    // ---------------------------------------------------------------
    // Happy path - a legitimate client target is accepted
    // ---------------------------------------------------------------

    public function test_legitimate_target_is_accepted(): void
    {
        $safe = $this->sanitizer()->sanitize('https://app.acme.test/login');

        self::assertSame('https://app.acme.test/login', $safe->canonical);
        self::assertSame('app.acme.test', $safe->host);
    }

    public function test_legitimate_target_with_query_is_accepted(): void
    {
        // Query strings carry "&" and "?" - these are NOT shell metacharacters
        // in a target, and must not be refused here (the argv-array invoker
        // neutralises them as defence in depth).
        $safe = $this->sanitizer()->sanitize('https://app.acme.test/search?q=1&page=2');

        self::assertSame('https://app.acme.test/search?q=1&page=2', $safe->canonical);
        self::assertSame('app.acme.test', $safe->host);
    }

    // ---------------------------------------------------------------
    // Command injection (SFR-SELF-005)
    // ---------------------------------------------------------------

    public function test_command_injection_in_host_is_refused(): void
    {
        $this->expectException(TargetRefused::class);

        // A ";" in the HOST is impossible in a real name - hostile.
        $this->sanitizer()->sanitize('https://app.acme.test;rm -rf /.test/');
    }

    public function test_command_injection_via_backtick_is_refused(): void
    {
        $this->expectException(TargetRefused::class);

        $this->sanitizer()->sanitize('https://app`id`.acme.test/');
    }

    // ---------------------------------------------------------------
    // Network pivoting / SSRF (SFR-SELF-005)
    // ---------------------------------------------------------------

    public function test_cloud_metadata_endpoint_is_refused(): void
    {
        $this->expectException(TargetRefused::class);

        $this->sanitizer()->sanitize('https://169.254.169.254/latest/meta-data/');
    }

    public function test_loopback_is_refused(): void
    {
        $this->expectException(TargetRefused::class);

        $this->sanitizer()->sanitize('http://127.0.0.1:6379/');
    }

    public function test_private_range_is_refused(): void
    {
        $this->expectException(TargetRefused::class);

        $this->sanitizer()->sanitize('https://10.0.0.5/admin');
    }

    public function test_ipv6_loopback_is_refused(): void
    {
        $this->expectException(TargetRefused::class);

        $this->sanitizer()->sanitize('https://[::1]/');
    }

    public function test_localhost_hostname_is_refused(): void
    {
        $this->expectException(TargetRefused::class);

        $this->sanitizer()->sanitize('https://localhost/');
    }

    // ---------------------------------------------------------------
    // Arbitrary tool flags (SFR-SELF-005)
    // ---------------------------------------------------------------

    public function test_flag_injection_is_refused(): void
    {
        $this->expectException(TargetRefused::class);

        // A host beginning with "-" would let the scanner read it as a flag
        // rather than an operand.
        $this->sanitizer()->sanitize('https://--script=evil.js.acme.test/');
    }

    // ---------------------------------------------------------------
    // Path traversal (SFR-SELF-005)
    // ---------------------------------------------------------------

    public function test_path_traversal_is_refused(): void
    {
        $this->expectException(TargetRefused::class);

        $this->sanitizer()->sanitize('https://app.acme.test/../../etc/passwd');
    }

    public function test_absolute_system_path_is_refused(): void
    {
        $this->expectException(TargetRefused::class);

        $this->sanitizer()->sanitize('https://app.acme.test//etc/shadow');
    }

    // ---------------------------------------------------------------
    // Length ceiling (SFR-SELF-005, smuggling guard)
    // ---------------------------------------------------------------

    public function test_oversized_target_is_refused(): void
    {
        $this->expectException(TargetRefused::class);

        $this->sanitizer()->sanitize('https://app.acme.test/' . str_repeat('a', 5000));
    }

    // ---------------------------------------------------------------
    // Non-http targets are out of scope (composes with SFR-AUTH-002)
    // ---------------------------------------------------------------

    public function test_non_http_scheme_is_refused(): void
    {
        $this->expectException(TargetRefused::class);

        // file:// is a filesystem hand-off, not a web scan.
        $this->sanitizer()->sanitize('file:///etc/passwd');
    }

    public function test_userinfo_target_is_refused_by_canonicalizer(): void
    {
        $this->expectException(TargetRefused::class);

        $this->sanitizer()->sanitize('https://user:pass@app.acme.test/');
    }

    // ---------------------------------------------------------------
    // Composition with ScannerAdapter - the hostile target never becomes
    // an argv element, because the executor refuses first.
    // ---------------------------------------------------------------

    public function test_scanner_adapter_refuses_a_pivoting_target(): void
    {
        $invoker = new SafeScannerInvoker($this->policy());

        // Hand the invoker in as the adapter's executor (the production seam).
        $adapter = new ScannerAdapter('nmap', '7.94', function (string $target) use ($invoker): array {
            return $invoker->run('nmap', $target);
        });

        $result = $adapter->run('https://169.254.169.254/latest/meta-data/');

        self::assertSame(ScannerResult::STATUS_REFUSED, $result->status);
        self::assertStringContainsString('internal', (string) $result->errorMessage);
    }

    // ---------------------------------------------------------------
    // REAL PROCESS: prove the invoker spawns via an argv ARRAY, so a hostile
    // target cannot break out into a command. We repoint the nmap binary at
    // the host `php` and pass our probe script as a platform-fixed flag, then
    // assert the spawned process saw the target as exactly ONE argv element
    // after "--" - not as a second command. This is the round-trip the
    // falsification probes cannot fake.
    // ---------------------------------------------------------------

    public function test_invoker_passes_target_as_single_operand_not_a_command(): void
    {
        $php = is_file(PHP_BINARY) ? PHP_BINARY : 'php';
        $policy = $this->policy();
        // Repoint the nmap entry at a safe, present binary and mark it allowed.
        $policy['tool_binaries'] = ['nmap' => $php];

        // A script that prints its argv as JSON so we can assert the target is
        // exactly ONE element after the POSIX "--" delimiter.
        $script = tempnam(sys_get_temp_dir(), 'scan');
        self::assertNotFalse($script, 'probe script tempfile');
        file_put_contents(
            $script,
            "<?php echo json_encode(['status'=>'ok','argv'=>array_slice(\$argv,1),'target'=>\$argv[count(\$argv)-1] ?? null]);\n"
        );

        $invoker = new SafeScannerInvoker($policy);
        $out = $invoker->run('nmap', 'https://app.acme.test/;rm -rf /', [$script]);

        self::assertIsArray($out);
        self::assertSame('ok', $out['status'] ?? null);
        // The trailing element is the target, verbatim - NOT a second command.
        self::assertSame('https://app.acme.test/;rm -rf /', $out['target'] ?? null);
        // It must be the ONLY element after the "--" delimiter: php's argv is
        // [script, ...flags, --, target], so array_slice($argv,1) drops the
        // script name and leaves exactly ['--', target]. A break-out would have
        // produced more entries than the delimiter + target (e.g. the "rm" as
        // a separate command would appear as an extra trailing element).
        $expectedArgv = ['--', 'https://app.acme.test/;rm -rf /'];
        self::assertSame($expectedArgv, $out['argv'] ?? []);

        @unlink($script);
    }

    public function test_invoker_refuses_unknown_tool_id(): void
    {
        $invoker = new SafeScannerInvoker($this->policy());

        $this->expectException(TargetRefused::class);
        $invoker->run('not-a-real-tool', 'https://app.acme.test/');
    }

    // ---------------------------------------------------------------
    // Pinning test - the shipped policy must keep the values it cites and the
    // PROPOSED status until ratified. Changing a number without changing this
    // test fails CI; that is the point (mirrors the other *_pins_its_* tests).
    // ---------------------------------------------------------------

    public function test_shipped_scanner_target_policy_pins_its_contract_terms(): void
    {
        $policy = $this->policy();

        self::assertSame('PROPOSED', $policy['status'] ?? null, 'SFR-SELF-005 policy is awaiting owner ratification; flip to RATIFIED on approval.');

        // The pivot ranges must match the network-pivot defence in ToolGateway
        // (FR-TOOL-003): removing one would reopen an internal destination.
        self::assertContains('169.254.0.0/16', $policy['blocked_v4_cidrs']);
        self::assertContains('10.0.0.0/8', $policy['blocked_v4_cidrs']);
        self::assertContains('127.0.0.0/8', $policy['blocked_v4_cidrs']);
        self::assertContains('192.168.0.0/16', $policy['blocked_v4_cidrs']);

        // Internal hostnames that must never be scannable.
        self::assertContains('localhost', $policy['blocked_internal_hosts']);
        self::assertContains('metadata.google.internal', $policy['blocked_internal_hosts']);

        // Command-injection metacharacters that must be refused in a host.
        $metachars = $policy['forbidden_shell_metacharacters'];
        foreach ([';', '|', '&', '$', '`', '>', '<'] as $char) {
            self::assertContains($char, $metachars, sprintf('Policy must refuse shell metacharacter "%s" (SFR-SELF-005 command injection).', $char));
        }

        // Path-traversal hand-offs.
        self::assertContains('..', $policy['forbidden_path_substrings']);
        self::assertContains('/etc/', $policy['forbidden_path_substrings']);
        self::assertContains('file://', $policy['forbidden_path_substrings']);

        // The length ceiling is bounded (not unlimited).
        self::assertGreaterThan(0, (int) ($policy['max_target_length'] ?? 0));
        self::assertLessThanOrEqual(8192, (int) ($policy['max_target_length'] ?? 0));

        // AC-002 binary allowlist must be present and non-empty.
        self::assertNotEmpty($policy['tool_binaries']);
    }

    public function test_incomplete_policy_is_refused_at_construction(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new TargetSanitizer(['blocked_v4_cidrs' => []]);
    }
}
