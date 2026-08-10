<?php

/**
 * P3-T5 Finding Engine — per-plan (support tier) SLA overrides.
 *
 * The ratified baseline in config/security/FINDING_SLA.php is the DEFAULT
 * plan. A finding's support tier (App\ManagedOps\SupportModel::TIERS:
 * basic / standard / premium / mission_critical) may tighten or loosen any
 * severity by listing it here. Severities NOT listed fall back to the
 * default — so a tier only needs to record the deltas, never repeat all five.
 *
 * RATIONALE (owner, 2026-08-10): "should become per-plan rather than global."
 * Tiers are plans; a higher tier commits to tighter remediation clocks. These
 * deltas are PROPOSED alongside the ratified default and use the same BOD 26-04
 * tier language (3-day forensic-triage ceiling for the tightest critical, the
 * 14-day KEV tier for medium, etc.). Ratify by editing here together with
 * tests/SecurityAgent/FindingEngineTest.php::test_sla_overridden_per_plan.
 *
 * @return array<string, array<string, int|null>>
 */

declare(strict_types=1);

return [
    // Loosest commitment: externalises more risk to the client window.
    'basic' => [
        'critical' => 72,   // 3 days
        'high' => 168,      // 7 days
        'medium' => 720,    // 30 days
        'low' => 2160,      // 90 days
    ],

    // Tightest commitment: managed, mission-critical estate.
    'premium' => [
        'critical' => 12,   // half a day
        'high' => 48,       // 2 days
        'medium' => 240,     // 10 days
    ],

    'mission_critical' => [
        'critical' => 4,    // inside the BOD 26-04 3-day forensic-triage ceiling
        'high' => 24,       // 1 day
        'medium' => 120,     // 5 days
        'low' => 720,       // 30 days
    ],

    // 'standard' is intentionally absent: it uses the ratified default.
];
