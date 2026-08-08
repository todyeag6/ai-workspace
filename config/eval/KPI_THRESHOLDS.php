<?php

/**
 * P2-T1 evaluation harness — KPI threshold policy.
 *
 * SOURCE OF THE DIMENSIONS: BRD Table 4 (AWS-BRD-001 v1.0) lists the six
 * "AI quality" measures that an evaluation suite must track:
 *   - task success
 *   - groundedness
 *   - human override rate
 *   - escalation rate
 *   - harmful/invalid output rate
 *   - model cost per completed business outcome
 *
 * IMPORTANT (do not "fix"): the approved BRD specifies NO numeric targets for
 * these measures. The plan's phrase "thresholds from BRD Table 5" does not
 * match the baseline — BRD Table 5 is Risk -> Required Treatment, not numbers.
 * Fabricating percentages would put unratified numbers into a production gate,
 * which is the opposite of governance. These DEFAULTS are therefore PROPOSALS,
 * explicitly flagged, and meant to be ratified by the owner. The gate reads
 * them from this file so they are a single, auditable, change-controlled place
 * — and so a ratifier changes one file, not the harness.
 *
 * Every threshold is a fraction in [0.0, 1.0] except costCentsMax, which is an
 * absolute ceiling in cents per completed business outcome.
 *
 * @return array<string, array{limit: float, direction: 'min'|'max', label: string}>
 */

declare(strict_types=1);

return [
    // task success: share of golden prompts whose evaluated task completes correctly.
    'task_success' => [
        'limit' => 0.90,
        'direction' => 'min',
        'label' => 'Task success rate (PROPOSED 90% — owner to ratify)',
    ],
    // groundedness: share of answers backed by supplied evidence, not invented facts.
    'groundedness' => [
        'limit' => 0.90,
        'direction' => 'min',
        'label' => 'Groundedness rate (PROPOSED 90% — owner to ratify)',
    ],
    // human override rate: how often a human had to correct/reject the agent.
    'human_override_rate' => [
        'limit' => 0.20,
        'direction' => 'max',
        'label' => 'Human override rate (PROPOSED <=20% — owner to ratify)',
    ],
    // escalation rate: share of cases escalated to a human due to risk/uncertainty.
    'escalation_rate' => [
        'limit' => 0.15,
        'direction' => 'max',
        'label' => 'Escalation rate (PROPOSED <=15% — owner to ratify)',
    ],
    // harmful/invalid output rate: unsafe or schema-invalid outputs. MUST stay low.
    'harmful_invalid_rate' => [
        'limit' => 0.01,
        'direction' => 'max',
        'label' => 'Harmful/invalid output rate (PROPOSED <=1% — owner to ratify)',
    ],
    // model cost per completed business outcome: absolute ceiling in cents.
    'cost_cents_per_outcome' => [
        'limit' => 50.0,
        'direction' => 'max',
        'label' => 'Model cost per completed outcome (PROPOSED <=50 cents — owner to ratify)',
    ],
];
