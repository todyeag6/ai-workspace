<?php

declare(strict_types=1);

/**
 * Packaged vertical offering: Lead Follow-Up MVP (P2-T5, BR-16 Phase 2).
 *
 * A repeatable engagement that bundles two agents — a Lead Analyst and a Lead
 * Router — each with its own BR-11.1 ownership roster, BRD Table 4 SLA targets,
 * and a standard support model, launched through a two-step workflow.
 *
 * This file is DATA, not logic. VerticalTemplate::fromFile() validates it
 * against the single source of valid vocabulary (AgentOwnership::roleNames(),
 * SlaRecord::types(), SupportModel::tiers()); a typo in any of those is a
 * loud InvalidArgumentException at load, not a silent mis-launch.
 *
 * The evaluation verdict that activates the bundle lives outside this file —
 * the launcher receives it from EvalHarness/EvaluationReleaseGate, so a package
 * can never self-activate.
 *
 * © AI WebScapes 2026
 */

return [
    'name' => 'Lead Follow-Up MVP',
    'description' => 'Bundled lead follow-up engagement: analysis, routing and SLA-backed managed support.',
    'purpose' => 'lead',
    'support' => [
        'tier' => 'standard',
        'boundary' => 'Client owns end-user data entry and first-line ticket handling; provider owns agent operation, patching and backup.',
        'contacts' => [
            ['role' => 'primary', 'channel' => 'email', 'target' => 'support@aiwebscapes.example'],
            ['role' => 'escalation', 'channel' => 'phone', 'target' => '+1-555-0100'],
        ],
    ],
    'agents' => [
        [
            'key' => 'analyst',
            'name' => 'Lead Analyst',
            'owner' => 'platform-ops',
            'purpose' => 'Analyse inbound leads and score follow-up priority.',
            'system_prompt' => 'You are a lead analyst. Read the submitted lead, classify intent, and score follow-up priority. Do not contact the lead.',
            'risk_class' => 'high',
            'allowed_tools' => ['crm_read', 'crm_write'],
            'data_classes' => ['contact', 'company'],
            'deployment_location' => 'cloud',
            'ownership' => [
                'business_owner' => 'biz@aiwebscapes.example',
                'technical_owner' => 'eng@aiwebscapes.example',
                'data_owner' => 'dpo@aiwebscapes.example',
                'security_owner' => 'sec@aiwebscapes.example',
                'acceptance_authority' => 'accept@aiwebscapes.example',
                'update_owner' => 'update@aiwebscapes.example',
                'backup_owner' => 'backup@aiwebscapes.example',
            ],
            'sla_targets' => [
                ['type' => 'patch', 'target_hours' => 72.0],
                ['type' => 'incident_response', 'target_hours' => 4.0],
                ['type' => 'backup_restore_test', 'target_hours' => 168.0],
            ],
        ],
        [
            'key' => 'router',
            'name' => 'Lead Router',
            'owner' => 'platform-ops',
            'purpose' => 'Route qualified leads to the correct owner or sequence.',
            'system_prompt' => 'You are a lead router. Given a scored lead, assign it to the correct owner or cadence. Never send external messages without an explicit human-approved step.',
            'risk_class' => 'high',
            'allowed_tools' => ['crm_write', 'email_send'],
            'data_classes' => ['contact', 'company'],
            'deployment_location' => 'cloud',
            'ownership' => [
                'business_owner' => 'biz@aiwebscapes.example',
                'technical_owner' => 'eng@aiwebscapes.example',
                'data_owner' => 'dpo@aiwebscapes.example',
                'security_owner' => 'sec@aiwebscapes.example',
                'acceptance_authority' => 'accept@aiwebscapes.example',
                'update_owner' => 'update@aiwebscapes.example',
                'backup_owner' => 'backup@aiwebscapes.example',
            ],
            'sla_targets' => [
                ['type' => 'patch', 'target_hours' => 72.0],
                ['type' => 'incident_response', 'target_hours' => 4.0],
                ['type' => 'backup_restore_test', 'target_hours' => 168.0],
            ],
        ],
    ],
    'launch_workflow' => [
        'workflow_id' => 'lead_followup_launch',
        'steps' => [
            ['type' => 'charge', 'risk' => 'low'],
            ['type' => 'reserve_stock', 'risk' => 'medium'],
        ],
    ],
];
