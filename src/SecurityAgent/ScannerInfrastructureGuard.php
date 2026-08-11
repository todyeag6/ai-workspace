<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use RuntimeException;

/**
 * SFR-SELF-001 - fail-closed isolation guard for the scanner infrastructure.
 *
 * The scanner is a SECURITY FUNCTION (it probes client surfaces for
 * weaknesses). SFR-SELF-001 [Must] requires it be "isolated from production
 * business systems and client tenants." This class is the DECIDER that enforces
 * that boundary before any process is spawned - it performs NO spawning, NO IO,
 * no clock, no socket. It is a pure predicate that throws TargetRefused when
 * the scanner's execution scope could reach production.
 *
 * WHY A CODE GUARD AND NOT JUST A COMPOSE NETWORK
 * ------------------------------------------------
 * The deny-by-default scanner_net in compose.yaml (SC-7(8)) is the deployment
 * posture, but posture is not an invariant unless something tests it. This
 * guard makes "scanner can see prod DB/Redis/creds" a REFUSED condition caught
 * at launch, not a hope that the deployment remembered to segment. CISA/FBI/
 * NSA Secure-by-Design Alert (2024-07-10): eliminate inherent flaws by design;
 * default-secure. A guard that refuses on missing/weak policy is default-secure.
 *
 * WHAT IT CHECKS (all fail-closed)
 * --------------------------------
 *  1. require_isolated_network is true (otherwise refuse - isolation is the
 *     mandated default, not opt-in).
 *  2. The reported scanner network equals scanner_network_name - i.e. the
 *     scanner is actually attached to the isolated segment, not app_net.
 *  3. None of forbidden_scope_dsns is present in the scanner's execution
 *     scope (prod DB / test DB / Redis DSNs).
 *  4. None of forbidden_scope_env_keys survives into the scanner's child
 *     environment (SafeScannerInvoker already sends a minimal env; this is the
 *     backstop that refuses if a key leaks through).
 *
 * If the policy is missing any required key, the constructor throws - the
 * scanner does not run on an unverified policy.
 *
 * © AI WebScapes 2026
 */
final class ScannerInfrastructureGuard
{
    private const REQUIRED_KEYS = [
        'require_isolated_network',
        'scanner_network_name',
        'forbidden_scope_dsns',
        'forbidden_scope_env_keys',
        'status',
    ];

    /**
     * @param array<string, mixed> $policy The decoded SCANNER_ISOLATION_POLICY.php.
     *
     * @throws RuntimeException When the policy is missing a required key.
     */
    public function __construct(private readonly array $policy)
    {
        foreach (self::REQUIRED_KEYS as $key) {
            if (!array_key_exists($key, $policy)) {
                throw new RuntimeException(sprintf(
                    'Scanner isolation policy is missing "%s"; refusing to construct an '
                    . 'incomplete SFR-SELF-001 guard (fail closed).',
                    $key
                ));
            }
        }
    }

    /**
     * Asserts the scanner is isolated from production scope.
     *
     * @param string         $scannerNetwork The Docker network the scanner
     *                              reports it is attached to.
     * @param list<string>   $scopeDsns      DSNs present in the scanner's
     *                              execution scope (prod/test DB, Redis, ...).
     * @param array<string,string> $scopeEnv Environment handed to the
     *                              scanner child process (backstop vs prod creds).
     *
     * @throws TargetRefused When isolation cannot be guaranteed.
     */
    public function assertIsolated(
        string $scannerNetwork,
        array $scopeDsns = [],
        array $scopeEnv = []
    ): void {
        // 1. Isolation is the mandated default, not opt-in.
        $required = $this->policy['require_isolated_network'] ?? null;
        if (!is_bool($required) || $required !== true) {
            throw TargetRefused::isolationNotRequired();
        }

        // 2. The scanner must be on the isolated segment, not app_net.
        $expectedNetwork = is_string($this->policy['scanner_network_name'])
            ? $this->policy['scanner_network_name']
            : '';
        if ($expectedNetwork === '' || $scannerNetwork !== $expectedNetwork) {
            throw TargetRefused::scannerOnWrongNetwork($scannerNetwork, $expectedNetwork);
        }

        // 3. No production DSN may be reachable from the scanner scope.
        $forbiddenDsns = is_array($this->policy['forbidden_scope_dsns'])
            ? $this->policy['forbidden_scope_dsns']
            : [];
        foreach ($forbiddenDsns as $forbidden) {
            if (!is_string($forbidden)) {
                continue;
            }
            foreach ($scopeDsns as $present) {
                if ($this->dsnEquals($present, $forbidden)) {
                    throw TargetRefused::scannerReachesForbiddenDsn($forbidden);
                }
            }
        }

        // 4. No production credential/env key may survive into the child env.
        $forbiddenKeys = is_array($this->policy['forbidden_scope_env_keys'])
            ? $this->policy['forbidden_scope_env_keys']
            : [];
        foreach ($forbiddenKeys as $key) {
            if (!is_string($key)) {
                continue;
            }
            if (array_key_exists($key, $scopeEnv)) {
                throw TargetRefused::scannerScopeLeaksSecret($key);
            }
        }
    }

    /**
     * Compares two DSNs case-insensitively after stripping whitespace, so a
     * scanner aimed at the production DB is refused even if the string differs
     * only in casing or trailing spaces (defence in depth, not exact-string).
     */
    private function dsnEquals(string $present, string $forbidden): bool
    {
        return strcasecmp(trim($present), trim($forbidden)) === 0;
    }
}
