<?php

/**
 * Scan Scheduler recurrence policy (P3 close-out: recurring scans).
 *
 * SOURCE OF THE REQUIREMENT: FRD section 2.36 ("Scan Scheduler") names
 * "One-time/recurring jobs" as a scheduler deliverable, and SFR-AUTH-001 [Must]
 * requires an authorization to carry a "validity period ... before scheduling."
 * Neither number is fixed by the approved baseline, so the values live here: one
 * auditable, change-controlled file a ratifier edits without touching the
 * scheduler, exactly as config/security/FINDING_SLA.php does for remediation
 * deadlines.
 *
 * STATUS: PROPOSED (owner to ratify). On ratification, flip this line to
 * RATIFIED with the date and KEEP
 * tests/SecurityAgent/ScanSchedulerTest.php::
 * test_shipped_scan_schedule_policy_pins_its_contract_terms — the test pins
 * every value below so an unsourced edit fails CI. Ratification raises the bar on
 * an edit; it does not remove it.
 *
 * ---------------------------------------------------------------------------
 * EXTERNAL GROUNDING (reviewed 2026-08-10 against the live publications)
 * ---------------------------------------------------------------------------
 * - NIST SP 800-53 Rev 5 (Dec 2020, current catalog) — SC-8 (Transmission
 *   Confidentiality and Integrity), CA-2 / CA-7 (continuous monitoring cadence)
 *   frame a "recurring scan" as a continuous-monitoring control with a defined
 *   cadence and an authority that expires (SC-8's protected, time-boxed channel).
 * - OWASP ASVS 5.0, V14.3 (automated vulnerability scanning in the SDLC) and
 *   V16 (logging) — periodic re-scanning is the expected control; this policy
 *   sets the cadence bounds the scheduler enforces.
 * - CISA *Binding Operational Directive 26-04* (2026-06-10) tier boundaries are
 *   already the basis for FINDING_SLA; a recurring scan's default cadence is
 *   chosen to sit at or inside the reassessment window those tiers imply.
 *
 * ---------------------------------------------------------------------------
 * WHY THESE NUMBERS
 * ---------------------------------------------------------------------------
 * - default_cadence 'weekly': a recurring engagement re-scans at least weekly,
 *   well inside any reasonable SLA, and is the smallest unit that keeps a trend
 *   report (P3-T8) meaningful across the 90-day window.
 * - min_cadence 'daily' / max_cadence 'monthly': the scheduler accepts only
 *   these three (allowlist, AC-002). 'none' is the one-shot path and is not a
 *   cadence.
 * - max_validity_days 365: matches the annual review cycle already cited by
 *   REMEDIATION_POLICY; an authorization older than a year must be re-issued
 *   (SFR-AUTH-001 "validity period").
 * - max_horizon_runs 12: a recurrence is scheduled at most a year out (12 weekly
 *   or 12 monthly) before it MUST be re-authorized — bounds the next_run_at
 *   burst a single scheduleRecurring() call can create.
 */

return [
    'status' => 'PROPOSED',
    'config_version' => 'scan-schedule-policy-2026-08-10',

    // The cadence the scheduler falls back to when a caller does not specify one.
    'default_cadence' => 'weekly',

    // Allowed recurrence values (the 'none' one-shot path is not a cadence).
    'allowed_cadences' => ['daily', 'weekly', 'monthly'],

    // SFR-AUTH-001 validity period: an authorization older than this (days) may
    // not be used to schedule a recurring run.
    'max_validity_days' => 365,

    // A single scheduleRecurring() call may chain at most this many future runs.
    'max_horizon_runs' => 12,

    // The named citation the audit trail records for a scheduled recurrence.
    'source_reference' => 'SFR-AUTH-001; FRD 2.36; SP800-53 CA-7',
];
