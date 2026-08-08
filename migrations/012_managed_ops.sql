-- © AI WebScapes 2026
-- Migration 012_managed_ops: the managed-operations substrate (P2-T4).
--
-- P2-T4 delivers the three managed-ops primitives the baseline mandates:
--   1. Ownership roster (BR-9.1 "update owner", "backup owner"; BR-11.1
--      business/technical/data/security owner + acceptance authority).
--   2. SLA tracking (BRD Table 4 "Security" KPI: patch SLA, incident
--      frequency, backup restore test success) — target vs observed with a
--      computed breach flag.
--   3. Support model surface (BR-9.1 "support boundary"; BR-12.6 incident
--      contacts, patching responsibility) is a pure value object, no schema.
--
-- IDEMPOTENCY CONTRACT (identical to 000..011): no ALTER, no DROP, no
-- trigger, no DELIMITER block. CREATE TABLE IF NOT EXISTS only. TestCase.php
-- re-applies this file per test, so it must be re-entrant. No semicolon inside
-- a comment or string literal.
--
-- tenant_id is carried denormalised for the same AC-001 reason as every other
-- table: App\Data\TenantRepository scopes every statement by it, and a table
-- without its own tenant column could only be scoped through a join the base
-- class does not write.

CREATE TABLE IF NOT EXISTS agent_ownership (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  agent_id BIGINT UNSIGNED NOT NULL,
  version_id BIGINT UNSIGNED NOT NULL,
  -- The five BR-11.1 accountable roles, plus the BR-9.1 update/backup owners.
  business_owner VARCHAR(255) NOT NULL DEFAULT '',
  technical_owner VARCHAR(255) NOT NULL DEFAULT '',
  data_owner VARCHAR(255) NOT NULL DEFAULT '',
  security_owner VARCHAR(255) NOT NULL DEFAULT '',
  acceptance_authority VARCHAR(255) NOT NULL DEFAULT '',
  update_owner VARCHAR(255) NOT NULL DEFAULT '',
  backup_owner VARCHAR(255) NOT NULL DEFAULT '',
  -- BR-9.1 "support boundary": the line beyond which the client owns the run.
  support_boundary VARCHAR(512) NOT NULL DEFAULT '',
  -- Append-only: reassigning ownership writes a NEW row, never an UPDATE, so
  -- the accountability history is intact (a release whose ownership can be
  -- silently rewritten is not a gate). assigned_by is the human who recorded it.
  assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  assigned_by VARCHAR(255) NOT NULL DEFAULT '',
  INDEX idx_ownership_agent (tenant_id, agent_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS agent_slas (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  agent_id BIGINT UNSIGNED NOT NULL,
  -- One of the BRD Table 4 security SLA types: 'patch', 'incident_response',
  -- 'backup_restore_test'. The vocabulary is enforced by the SLA repository,
  -- not by an enum, so a new type is a code change not a migration.
  sla_type VARCHAR(64) NOT NULL,
  -- Target and observed, in hours, so breach = observed_hours > target_hours.
  target_hours DECIMAL(10,2) NOT NULL,
  observed_hours DECIMAL(10,2) NOT NULL,
  -- Derived at insert time by the SlaRecord value object (immutable row), so
  -- it is queryable without re-deriving and cannot drift from the numbers.
  breached TINYINT(1) NOT NULL DEFAULT 0,
  measured_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_sla_agent (tenant_id, agent_id),
  INDEX idx_sla_breached (tenant_id, breached)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
