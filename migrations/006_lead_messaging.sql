-- © AI WebScapes 2026
-- Migration 006_lead_messaging: the tables P1-T12 needs for messaging,
-- opt-out, tasks and AI-field corrections.
--
-- Covers LFR-MSG-001 (idempotent send), LFR-MSG-002 (opt-out honoured,
-- recipient never messaged), LFR-TASK-001 (a task can be opened against a
-- lead), LFR-DASH-004 (AI-field correction is append-only) and LBR-5.4
-- (suppression list).
--
-- lead_tasks and lead_field_corrections arrive with migration 005 (lead
-- lifecycle) - this file adds only what 005 did not:
--   * message_opt_outs   - the suppression list a send consults first.
--   * message_deliveries - the idempotency plus audit record of what was sent.
--
-- IDEMPOTENCY CONTRACT - same as every other migration: CREATE TABLE IF NOT
-- EXISTS, inline indexes, no DROP/ALTER, no raw semicolons in comments.
--
-- NOTE ON NUMBERING: the handoff labelled T13's audit migration as
-- 006_audit.sql. Because T12 genuinely needs new tables this file takes the
-- 006 slot and T13's audit file becomes 007_audit.sql so the two never
-- collide on the 006 prefix. Lexicographic order keeps apply order correct.
-- This is a documentation-level reconciliation only (no security change).

CREATE TABLE IF NOT EXISTS message_opt_outs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  email VARCHAR(190) NOT NULL,
  reason VARCHAR(64) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_message_opt_outs_tenant_email (tenant_id, email),
  KEY idx_message_opt_outs_tenant (tenant_id),
  CONSTRAINT fk_message_opt_outs_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One delivery row per (tenant, lead, kind). The unique key is what makes a
-- retry idempotent at the storage layer: a second acknowledgement for the same
-- lead cannot be inserted, so send can be retried without duplicating the
-- outbound message (LFR-MSG-001). The body is snapshotted so the exact
-- wording that left the system is reconstructable later (LBR-5.3 / audit).
CREATE TABLE IF NOT EXISTS message_deliveries (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  lead_id BIGINT UNSIGNED NULL,
  kind VARCHAR(32) NOT NULL,
  channel ENUM('email', 'sms', 'internal') NOT NULL DEFAULT 'email',
  recipient VARCHAR(190) NULL,
  template_code VARCHAR(64) NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_message_deliveries_tenant_lead_kind (tenant_id, lead_id, kind),
  KEY idx_message_deliveries_tenant (tenant_id),
  KEY idx_message_deliveries_lead (tenant_id, lead_id),
  CONSTRAINT fk_message_deliveries_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_message_deliveries_lead FOREIGN KEY (lead_id) REFERENCES leads (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
