<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use Closure;
use RuntimeException;
use Throwable;

/**
 * A version-pinned, sandboxed scanner adapter (SFR-SCAN-002, SFR-SCAN-003,
 * SFR-SELF-002).
 *
 * WHY THIS IS NOT ConnectorExecutor
 * ---------------------------------
 * App\Connectors\ConnectorExecutor is the actor for BUSINESS connectors, and
 * reusing it here would put client CRM traffic and offensive-tooling traffic
 * behind the same seam. SFR-SELF-002 requires security tooling to be sandboxed,
 * version-pinned and DISABLED when untrusted - three properties the business
 * connector path neither has nor should acquire. So this is a separate,
 * deliberately smaller surface.
 *
 * WHY THE EXECUTOR IS INJECTED
 * ----------------------------
 * The thing that touches the network is a callable handed in from outside; in
 * production it is the sandboxed, permission-minimised process wrapper, and in
 * a test it is a closure. That keeps this class PURE: it decides how to
 * classify what came back, and every classification path - success, throw,
 * error-shaped output, unrecognised status, refusal - is provable without
 * opening a socket. The DECIDE-vs-ACT split of ScopeManager and SafetyMonitor,
 * applied to the one component that unavoidably has an actor in it.
 *
 * WHY A FAILURE CAN NEVER BECOME A FINDING
 * ----------------------------------------
 * SFR-SCAN-003. There is exactly one route to STATUS_FINDING in this class:
 * the executor RETURNED, and its structured output explicitly said `finding`.
 * A thrown exception, an error-shaped payload, an unparseable payload and an
 * unrecognised status all converge on ScannerResult::failure(), carrying the
 * message and exit code so the failure is EVIDENCED rather than silent. An
 * absent result is not a clean target.
 *
 * WHAT THIS CLASS DOES NOT DO: it writes nothing. Persisting the result is the
 * evidence store's job; handing back a ScannerResult is this one's.
 *
 * © AI WebScapes 2026
 */
final class ScannerAdapter
{
    /** Statuses an adapter may report about the TARGET, i.e. a real run. */
    private const TARGET_STATUSES = [
        ScannerResult::STATUS_OK,
        ScannerResult::STATUS_INFO,
        ScannerResult::STATUS_FINDING,
    ];

    /** Statuses that describe the RUN failing. Never a target claim. */
    private const RUN_FAILURE_STATUSES = [
        ScannerResult::STATUS_ERROR,
        ScannerResult::STATUS_TIMEOUT,
        ScannerResult::STATUS_REFUSED,
    ];

    /**
     * The injected actor. Stored as a Closure because `callable` is not a
     * legal property type, and closures cannot be re-bound from outside.
     *
     * @var Closure(string): mixed
     */
    private readonly Closure $executor;

    /**
     * @param string   $name     The pinned tool identity, e.g. "nmap".
     * @param string   $version  The pinned tool version, e.g. "7.94" (SFR-SELF-002).
     * @param callable $executor Receives the target, returns raw output or throws.
     * @param bool     $enabled  False for an untrusted or quarantined tool.
     */
    public function __construct(
        private readonly string $name,
        private readonly string $version,
        callable $executor,
        private readonly bool $enabled = true,
    ) {
        if (trim($name) === '') {
            throw new RuntimeException('A scanner adapter must be named.');
        }

        // An unpinned adapter is the thing SFR-SELF-002 forbids: a result that
        // cannot say which build produced it cannot be reproduced or trusted.
        if (trim($version) === '') {
            throw new RuntimeException(sprintf(
                'Scanner adapter "%s" must pin a tool version (SFR-SELF-002).',
                $name
            ));
        }

        $this->executor = $executor(...);
    }

    public function name(): string
    {
        return $this->name;
    }

    public function version(): string
    {
        return $this->version;
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * Runs the adapter against one target and returns a machine-readable
     * result. This method never throws for a tool failure - a failure IS a
     * result (SFR-SCAN-003).
     */
    public function run(string $target): ScannerResult
    {
        $subject = trim($target);

        if (!$this->enabled) {
            // SFR-SELF-002: the executor is not merely ignored, it is never
            // reached - a disabled tool does not get to touch the network.
            return ScannerResult::refused(
                $this->name,
                $subject === '' ? 'unspecified-target' : $subject,
                sprintf(
                    'Scanner "%s" %s is disabled and was not run (SFR-SELF-002).',
                    $this->name,
                    $this->version
                )
            );
        }

        if ($subject === '') {
            return ScannerResult::failure(
                $this->name,
                'unspecified-target',
                'No target was supplied, so no scan was attempted.'
            );
        }

        try {
            $raw = ($this->executor)($subject);
        } catch (TargetRefused $e) {
            // A downstream guard (SFR-SELF-005 / scope) refused the target
            // before a run could even begin. That is a refusal, not a failure
            // of the tool, and must not be reported as a finding about the
            // target. Surface it as STATUS_REFUSED with the guard's reason.
            return ScannerResult::refused($this->name, $subject, $e->getMessage());
        } catch (Throwable $e) {
            // The tool broke. That is a fact about the TOOL, recorded with its
            // evidence - not a fact about the target (SFR-SCAN-003).
            return ScannerResult::failure($this->name, $subject, $e->getMessage(), $this->exitCodeOf($e));
        }

        return $this->classify($subject, $raw);
    }

    /**
     * Turns whatever the executor returned into a typed result. PURE: no IO,
     * no clock beyond the result's own timestamp, no invention of findings.
     */
    private function classify(string $target, mixed $raw): ScannerResult
    {
        if (is_string($raw)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                return $this->fromStructured($target, $this->stringKeyed($decoded));
            }

            // Unstructured output is reported AS output, never mined for
            // findings: SFR-SCAN-002 wants machine-readable results, and text
            // that has to be regexed is how a failure becomes a vulnerability.
            return new ScannerResult(
                $this->name,
                $target,
                ScannerResult::STATUS_INFO,
                ['output' => $raw]
            );
        }

        if (is_array($raw)) {
            return $this->fromStructured($target, $this->stringKeyed($raw));
        }

        return ScannerResult::failure(
            $this->name,
            $target,
            sprintf(
                'Scanner "%s" returned a %s, which is not a machine-readable result (SFR-SCAN-002).',
                $this->name,
                get_debug_type($raw)
            )
        );
    }

    /**
     * @param array<string, mixed> $output
     */
    private function fromStructured(string $target, array $output): ScannerResult
    {
        $status = $this->stringOf($output['status'] ?? null);
        $error = $this->stringOf($output['error'] ?? $output['error_message'] ?? null);
        $exitCode = $this->intOf($output['exit_code'] ?? null);

        // A tool that reports its own failure is believed about the failure -
        // and only about the failure.
        if (in_array($status, self::RUN_FAILURE_STATUSES, true) || $error !== '') {
            $message = $error !== ''
                ? $error
                : sprintf('Scanner "%s" reported status "%s".', $this->name, $status);

            if ($status === ScannerResult::STATUS_TIMEOUT || $status === ScannerResult::STATUS_REFUSED) {
                return new ScannerResult(
                    $this->name,
                    $target,
                    $status,
                    [],
                    $message,
                    $exitCode > 0 ? $exitCode : 1
                );
            }

            return ScannerResult::failure(
                $this->name,
                $target,
                $message,
                $exitCode > 0 ? $exitCode : 1
            );
        }

        if ($status !== '' && !in_array($status, self::TARGET_STATUSES, true)) {
            // An unrecognised status is a broken adapter contract. Refusing to
            // guess is the point: the tempting guess is "it probably means it
            // found something", which is precisely SFR-SCAN-003's failure mode.
            return ScannerResult::failure(
                $this->name,
                $target,
                sprintf(
                    'Scanner "%s" reported the unrecognised status "%s"; refusing to interpret it '
                    . 'as a target finding (SFR-SCAN-003).',
                    $this->name,
                    $status
                )
            );
        }

        return new ScannerResult(
            $this->name,
            $target,
            $status === '' ? ScannerResult::STATUS_INFO : $status,
            $this->dataOf($output),
            null,
            $exitCode
        );
    }

    /**
     * @param  array<string, mixed> $output
     * @return array<string, mixed>
     */
    private function dataOf(array $output): array
    {
        if (array_key_exists('data', $output)) {
            return is_array($output['data']) ? $this->stringKeyed($output['data']) : [];
        }

        // No explicit data envelope: the payload IS the data, minus the
        // control fields the adapter contract reserves.
        $data = $output;
        unset($data['status'], $data['error'], $data['error_message'], $data['exit_code']);

        return $data;
    }

    /**
     * @param  array<array-key, mixed> $values
     * @return array<string, mixed>
     */
    private function stringKeyed(array $values): array
    {
        $clean = [];
        foreach ($values as $key => $value) {
            $clean[(string) $key] = $value;
        }

        return $clean;
    }

    private function stringOf(mixed $value): string
    {
        return is_scalar($value) ? trim((string) $value) : '';
    }

    private function intOf(mixed $value): int
    {
        return is_scalar($value) ? (int) $value : 0;
    }

    /**
     * A thrown tool failure always carries a non-zero exit code, so a caller
     * cannot mistake it for a clean run that simply found nothing.
     */
    private function exitCodeOf(Throwable $e): int
    {
        $code = $e->getCode();

        return is_int($code) && $code > 0 ? $code : 1;
    }
}
