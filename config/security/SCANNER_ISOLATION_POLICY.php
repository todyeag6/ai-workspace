<?php

/**
 * SFR-SELF-001 - scanner infrastructure isolation policy.
 *
 * SOURCE OF THE REQUIREMENT
 * --------------------------
 * FRD section 6, SFR-SELF-001 [Must]: "The scanner infrastructure shall be
 * isolated from production business systems and client tenants."
 *
 * WHY THESE STRINGS LIVE HERE
 * ---------------------------
 * As with config/security/SCANNER_TARGET_POLICY.php and the other ratifiable
 * policy files, the approved baseline sets NO specific network names or
 * forbidden-scope DSNs. Those are policy decisions, not code, and they are
 * kept in this single auditable, change-controlled file so a ratifier edits
 * the policy without touching the engine. App\SecurityAgent\
 * ScannerInfrastructureGuard reads this file; if a value here is wrong, the
 * fix is here, not in the class.
 *
 * THE GUARD IS FAIL-CLOSED: a missing key or an unreadable file means the
 * policy object refuses to construct, and no scan launches. SFR-SELF-001 says
 * "shall be isolated" - the default is isolation, and an incomplete policy
 * cannot weaken it.
 *
 * EXTERNAL GROUNDING (reviewed 2026-08-11, MOST RECENT official sources)
 * -----------------------------------------------------------------------
 * - NIST SP 800-53 Rev 5 (current catalog, errata ongoing):
 *     * SC-2  Application Partitioning
 *     * SC-3  Security Function Isolation (the scanner is a security function;
 *             it is isolated from non-security business code by an isolation
 *             boundary - here, a separate Docker network + a fail-closed guard)
 *     * SC-7  Boundary Protection, and SC-7(8) Deny by Default (the scanner
 *             network attaches to NO production service; traffic is denied
 *             unless explicitly permitted)
 * - CISA Zero Trust Maturity Model (2023), Network pillar + microsegmentation:
 *     "segmentation that prevents lateral movement even when perimeter
 *     defenses are breached." This is the current, on-point framing - the
 *     scanner_net is a microsegment that cannot reach db/redis.
 * - CISA/FBI/NSA Secure-by-Design Alert (2024-07-10): manufacturers should
 *     "eliminate inherent flaws by design" and ship secure by default. The
 *     guard refuses a scan the moment production scope is detectable, rather
 *     than hoping the deployment remembered to segment.
 *
 * NOTE ON ENFORCEMENT DEPTH: the guard is the verifiable, testable contract.
 * The compose.yaml scanner_net (deny-by-default, db/redis NOT attached) is the
 * deployment posture the guard checks. Full live network isolation cannot be
 * proven by the current single-container test harness; it is covered by the
 * pen-test window (SEC-009 / SFR-AUTH-001). The guard + compose declaration
 * together implement SC-3 + SC-7(8); the e2e proof is an open item, not a
 * silent gap.
 *
 * STATUS: PROPOSED. Owner to ratify (flip this header to RATIFIED). Until then
 * the pinning test
 * tests/SecurityAgent/ScannerIsolationTest.php::
 * test_shipped_scanner_isolation_policy_pins_its_contract_terms stays RED on
 * the PROPOSED state and pins the specific values once ratified, so an
 * unsourced edit fails CI.
 *
 * @return array{
 *     require_isolated_network: bool,
 *     scanner_network_name: string,
 *     forbidden_scope_dsns: list<string>,
 *     forbidden_scope_env_keys: list<string>,
 *     status: string
 * }
 */

declare(strict_types=1);

return [
    // If true, the scanner MUST run on the network named below and the guard
    // refuses to launch a scan whose execution scope could reach production.
    'require_isolated_network' => true,

    // The Docker network the scanner is attached to. The guard asserts the
    // running scanner reports this name; compose.yaml attaches ONLY this
    // network to the scanner surface (db/redis are on app_net, not here).
    'scanner_network_name' => 'scanner_net',

    // DSNs the scanner must never be able to reach - the production business
    // database and the shared Redis. If any of these appears in the scanner's
    // execution scope, the guard refuses (SC-7 boundary protection). These are
    // the values compose.yaml injects into the app container; the guard makes
    // "scanner can see prod DB" a treated, refused condition, not an accident.
    'forbidden_scope_dsns' => [
        'mysql:host=db;dbname=aiwebscapes;charset=utf8mb4',
        'mysql:host=db;dbname=aiwebscapes_test;charset=utf8mb4',
        'tcp://redis:6379',
    ],

    // Environment variable names that, if present in the scanner's child
    // environment, would hand it production credentials or connection strings.
    // SafeScannerInvoker already builds a minimal child env (PATH + LC_ALL
    // only); the guard refuses if any of these keys survive into scope.
    'forbidden_scope_env_keys' => [
        'DB_DSN',
        'TEST_DB_DSN',
        'REDIS_DSN',
        'AI_LOCAL_BASE_URL',
        'APP_KEY',
    ],

    // Flip to 'RATIFIED' once the owner approves the values above.
    'status' => 'PROPOSED',
];
