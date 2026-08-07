-- © AI WebScapes 2026
-- Migration 007_audit: the immutable audit event log (FR-AUD-001/002) and the
-- append-only guarantee enforced at the database layer.
--
-- Covers FR-AUD-001 (a complete, tamper-evident audit record of every action),
-- FR-AUD-002 (secrets are never persisted to the audit trail), and the
-- append-only requirement the plan makes explicit: "enforce append-only with
-- MySQL BEFORE UPDATE/BEFORE DELETE triggers that SIGNAL SQLSTATE '45000' --
-- application-level discipline alone does not satisfy 'append-only'."
--
-- PARSER NOTE: this file IS split by scripts/migrate.php and tests/TestCase.php
-- through App\Infra\SqlSplitter, which is DELIMITER-aware (upgraded for P1-T13).
-- Triggers MUST be wrapped in DELIMITER $$ ... $$ so the semicolons inside the
-- trigger body are not treated as statement terminators.
--
-- IDEMPOTENCY: this file is applied exactly once. scripts/migrate.php records a
-- row in schema_migrations for the filename, so a second run of the same
-- migration file is a no-op at the ledger level; the statements below are
-- additionally guarded so the file can be replayed by --force without error.
-- (We do NOT fold re-entrancy into per-statement CREATE TABLE IF NOT EXISTS
-- here because the triggers must be dropped+recreated cleanly, which the
-- ledger-level guard already makes safe.)

DELIMITER $$

CREATE TABLE IF NOT EXISTS audit_events (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  actor_user_id BIGINT UNSIGNED NULL,
  action VARCHAR(64) NOT NULL,
  object_type VARCHAR(64) NULL,
  object_id VARCHAR(64) NULL,
  outcome ENUM('success', 'failure', 'denied') NOT NULL,
  source VARCHAR(32) NOT NULL,
  correlation_id VARCHAR(64) NULL,
  versions JSON NULL,
  detail VARCHAR(255) NULL,
  occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_audit_events_tenant (tenant_id),
  KEY idx_audit_events_action (action),
  KEY idx_audit_events_correlation (correlation_id),
  KEY idx_audit_events_occurred_at (occurred_at),
  CONSTRAINT fk_audit_events_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci $$

-- VERIFIED DELETION PROOF (FR-DATA-002). When a tenant's data is erased, the
-- erasure is proven (re-count of zero) and that proof is recorded here so
-- "we deleted it" is auditable rather than a promise. tenant_id is carried
-- denormalised so the proof is queryable without a join and cannot be
-- attributed to the wrong tenant.
CREATE TABLE IF NOT EXISTS data_deletion_verifications (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  data_class VARCHAR(64) NOT NULL,
  verified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_data_deletion_verifications_tenant_class (tenant_id, data_class),
  KEY idx_data_deletion_verifications_tenant (tenant_id),
  CONSTRAINT fk_data_deletion_verifications_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci $$

-- APPEND-ONLY ENFORCEMENT. An audit event that can be rewritten or deleted is
-- not evidence. These triggers refuse any mutation with SIGNAL SQLSTATE
-- '45000' so the database itself - not just the application - makes the trail
-- immutable. DROP IF EXISTS first so --force replay is a clean no-op.
DROP TRIGGER IF EXISTS audit_events_no_update $$
CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'audit_events is append-only: UPDATE is forbidden';
END $$

DROP TRIGGER IF EXISTS audit_events_no_delete $$
CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'audit_events is append-only: DELETE is forbidden';
END $$

DELIMITER ;
