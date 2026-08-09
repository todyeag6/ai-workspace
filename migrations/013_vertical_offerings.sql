-- © AI WebScapes 2026
-- Migration 013_vertical_offerings: the launched-offering ledger (P2-T5).
--
-- A "packaged vertical offering" composes the already-built modules
-- (AgentRegistry registration, EvaluationReleaseGate activation,
-- AgentOwnershipRepository accountability, SlaRepository targets,
-- WorkflowBuilder launch validation) into one named, repeatable engagement.
-- This table is the audit trail of a launch: which template, by whom, when,
-- and whether the offering was ACTIVATED (the eval gate passed) or left
-- DISABLED (the gate refused it — recorded, not lost).
--
-- IDEMPOTENCY CONTRACT (identical to 000..012): no ALTER, no DROP, no trigger,
-- no DELIMITER block. CREATE TABLE IF NOT EXISTS only. TestCase.php re-applies
-- this file per test, so it must be re-entrant. No semicolon inside a comment
-- or string literal.
--
-- tenant_id is carried denormalised for the same AC-001 reason as every other
-- table: App\Data\TenantRepository scopes every statement by it.

CREATE TABLE IF NOT EXISTS launched_offerings (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  -- The template's own name (free text, the human-facing offering name).
  template_name VARCHAR(255) NOT NULL,
  -- How many bundled agents this launch registered.
  agent_count INT UNSIGNED NOT NULL DEFAULT 0,
  -- 1 once the eval gate passed and the agents were activated; 0 while the
  -- offering is recorded but the agents remain DISABLED (gate refused).
  activated TINYINT(1) NOT NULL DEFAULT 0,
  -- The evaluation verdict's failing KPIs, stored for the audit trail when the
  -- gate refused activation (empty when activated).
  failed_kpis VARCHAR(512) NOT NULL DEFAULT '',
  -- Human who launched the offering (the recorded launcher, not the AI).
  launched_by VARCHAR(255) NOT NULL DEFAULT '',
  launched_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  -- UNIQUE within the tenant so a re-launch of the same template is a key
  -- collision the caller can detect rather than a duplicate row.
  UNIQUE KEY uq_tenant_template (tenant_id, template_name),
  INDEX idx_launched_tenant (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
