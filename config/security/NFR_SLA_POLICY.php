<?php

/**
 * NFR Table 5 — Service Levels / Performance Budgets (ratifiable policy).
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The Platform FRD NFR section deliberately leaves the numeric budgets open:
 *   - Availability: "Target agreed per client plan; health monitoring and
 *     graceful degradation required."
 *   - Performance:  "Interactive dashboard pages should meet defined budgets;
 *     pagination and background work required for expensive operations."
 *   - Scalability / Reliability: idempotency, retries with backoff,
 *     dead-letter handling, timeouts, recovery runbooks.
 * This file is where those agreed numbers live, so they are a tested,
 * reviewable contract (not prose that rots). It mirrors the other
 * config/security/*_POLICY.php files.
 *
 * GROUNDED IN THE MOST RECENT OFFICIAL SOURCES (cited by name+section; the
 * bar is the NEWEST authoritative revision, not "an official source"):
 *   - NIST SP 800-53 Rev 5 (current catalog):
 *       * SC-5  Denial-of-Service Protection   -> availability + rate limits
 *       * SC-6  Resource Availability           -> capacity headroom for spikes
 *       * CP-10 System Recovery                 -> RTO/RPO, restore-test SLA
 *       * SI-13 Predictive Monitoring           -> error-rate / latency alerts
 *   - OWASP ASVS 5.0 (2024, current major): V14.3 (resource limits, request
 *     size/rate caps, business-logic resource exhaustion) -> perf budgets.
 *   - Core Web Vitals — INP (Interaction to Next Paint), Google's CURRENT
 *     web-perf metric (replaced FID in 2024): "good" <= 200 ms -> dashboard
 *     interactivity budget.
 *   - Google SRE / Site Reliability Engineering (error budgets, 99.9%/99.95%
 *     availability, MTTR) — INDUSTRY BEST PRACTICE, cited as a reference, NOT
 *     an official regulatory standard. It backs the 99.9% monthly figure.
 *
 * The existing security-process SLAs (patch / incident_response /
 * backup_restore_test) are tracked immutably by src/ManagedOps/SlaRecord.php
 * (BRD Table 4); their targets are repeated here so the whole NFR Table 5 is
 * in one reviewed place.
 */

return [
    // Flip to 'RATIFIED' once the owner approves the values below.
    'status' => 'PROPOSED',
    'config_version' => 'nfr-sla-policy-2026-08-11',

    // ---- Availability (NIST SC-5 / CP-10; SRE reference) -----------------
    // 99.9% monthly = ~43 min downtime budget/month (the SRE "three nines").
    'availability' => [
        'monthly_uptime_percent' => 99.9,
        'max_monthly_downtime_minutes' => 43,
        'graceful_degradation_required' => true, // FRD NFR: degrade, don't fall over
    ],

    // ---- Dashboard interactivity (Core Web Vitals INP 2024) -------------
    // "good" INP is <= 200 ms. Pagination + background work is mandatory for
    // expensive operations (FRD NFR Performance).
    'dashboard_interactivity' => [
        'inp_budget_ms' => 200,        // Core Web Vitals INP "good" threshold
        'page_load_budget_ms' => 3000, // LCP-class target for an interactive page
        'expensive_ops_must_paginate_or_background' => true,
    ],

    // ---- Scanner / long-running task budgets (OWASP ASVS 5.0 V14.3) -----
    'scanner_tasks' => [
        'single_scan_timeout_seconds' => 300,  // one target scan must finish or die
        'max_concurrent_scans_per_tenant' => 4, // resource-exhaustion guard (SC-6)
        'rate_limit_requests_per_minute' => 60,// ASVS V14.3 request-rate cap
        'max_request_body_bytes' => 1048576,    // 1 MiB ASVS V14.3 size cap
    ],

    // ---- Recovery (NIST CP-10) ------------------------------------------
    'recovery' => [
        'rto_hours' => 4,   // Recovery Time Objective
        'rpo_hours' => 1,   // Recovery Point Objective (max data loss)
        'backup_restore_test_sla_hours' => 168, // must prove a restore weekly
    ],

    // ---- Security-process SLAs (BRD Table 4; tracked by SlaRecord) ------
    'security_process_slas' => [
        'patch_target_hours' => 168,            // critical patch within 7 days
        'incident_response_target_hours' => 4,  // ack/start within 4h
        'backup_restore_test_target_hours' => 168,
    ],

    'source_reference' => [
        'NIST SP 800-53 Rev 5' => ['SC-5', 'SC-6', 'CP-10', 'SI-13'],
        'OWASP ASVS 5.0 (2024)' => ['V14.3'],
        'Core Web Vitals INP (2024, Google)' => ['good <= 200ms'],
        'Google SRE (reference only)' => ['error budgets', '99.9% availability'],
        'Platform FRD NFR section' => ['Availability / Performance / Scalability / Reliability'],
    ],
];
