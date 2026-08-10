<?php

/**
 * P3-T6 AI Triage Assistant — operating policy.
 *
 * SOURCE OF THE REQUIREMENT: FRD section 2 gives the AI Triage Assistant one
 * job — "Summarize and prioritize evidence under strict non-authoritative
 * policy" — and section 3 bounds it with two [Must] requirements:
 *
 *   SFR-AI-001  AI may summarize and suggest severity/remediation but shall
 *               not alter confirmed status, close findings, or authorize risk
 *               acceptance without human decision.
 *   SFR-AI-002  Untrusted target content shall be treated as data and shall
 *               not control the AI system or invoke tools.
 *
 * IMPORTANT (do not "fix" by hardcoding these into the component): as with
 * config/security/FINDING_SLA.php, the approved baseline specifies NO numbers
 * here — no token budget, no timeout, no length cap. Those are deployment
 * parameters, so they live in this one auditable, change-controlled file
 * rather than as opaque constants inside TriageAssistant. The SECURITY
 * decisions below (data classification, cost ceiling) are deliberately in the
 * same file so that loosening one is a visible, reviewable edit and not a
 * quiet constant change buried in a class.
 *
 * STATUS: PROPOSED (owner to ratify). The values are defensible defaults, not
 * baseline facts. On ratification, flip this line to RATIFIED with the date
 * and KEEP tests/SecurityAgent/TriageAssistantTest.php::
 * test_shipped_triage_policy_pins_its_security_decisions — that test pins the
 * three security-critical entries so an unsourced edit fails CI.
 *
 * ---------------------------------------------------------------------------
 * WHY data_classification IS 'restricted' AND WHY THAT IS THE LOAD-BEARING LINE
 * ---------------------------------------------------------------------------
 * The material this component sends to a model is a catalogue of a client's
 * unfixed vulnerabilities plus the evidence needed to reproduce them. That is
 * the single most damaging document the platform holds about a client, and it
 * is exactly what an attacker would want. App\AI\CloudAdapter refuses to build
 * a request body for 'restricted' data (FR-AI-005), so declaring the triage
 * call restricted here means the finding corpus has NO egress path to a hosted
 * provider — enforced by the adapter, not by a reviewer noticing.
 *
 * This also satisfies SFR-SELF-003 (outbound access restricted to authorized
 * targets and required update services): a third-party model API is neither.
 *
 * cost_limit_cents and cost_per_thousand_tokens_cents are 0 for the same
 * reason, stated as money: a triage call that costs anything is a triage call
 * that left the premises. A future paid-provider deployment must change this
 * file, and that change is the review.
 *
 * @return array<string, int|string>
 */

declare(strict_types=1);

return [
    // The version stamp recorded on every AIRequest this policy produces, so
    // an audit row can name the policy the suggestion was produced under
    // (FR-AI-002 "configuration version", SFR-AUD-001).
    'config_version' => 'security-triage-policy-2026-08-10',

    // See the header. 'restricted' is what closes the cloud egress path.
    'data_classification' => 'restricted',

    // Prompt budget. Checked by AIGateway BEFORE the adapter is touched, so an
    // oversized prompt costs nothing. 8000 tokens is roughly a 32k-character
    // prompt: comfortably more than one finding plus its evidence, and far
    // less than a context window an attacker could stuff with instructions.
    'token_limit' => 8000,

    // Zero, deliberately. See the header: a triage call must not cost money,
    // because a call that costs money is a call that left the premises.
    'cost_limit_cents' => 0,
    'cost_per_thousand_tokens_cents' => 0,

    // A local model on the same host. Long enough for a slow generation on a
    // loaded box, short enough that a wedged model does not hold a scan open.
    'timeout_seconds' => 120,

    // The hard ceiling on untrusted target content admitted into one prompt,
    // in characters. This is a SECURITY limit, not an ergonomic one: it caps
    // how much attacker-controlled text can be placed in front of the model in
    // a single call, and it is checked before the prompt is assembled so an
    // enormous scraped page is refused rather than truncated into a shape
    // nobody reviewed. Roughly a quarter of the token budget, leaving room for
    // the operator instructions that must not be crowded out.
    'max_untrusted_chars' => 24000,

    // Ceilings on what the model is allowed to hand back, applied before the
    // suggestion is stored. A model (or an injection that reached it) does not
    // get to write an unbounded blob into a finding row that a human will
    // later read in a report.
    'max_summary_chars' => 1200,
    'max_remediation_chars' => 2000,
];
