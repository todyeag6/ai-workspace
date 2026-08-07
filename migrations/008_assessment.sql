-- © AI WebScapes 2026
-- Migration 008_assessment: the tenant-scoped assessment store behind the
-- Business-AI Assessment Framework (BAAF-001..006, FR-ASMT-001/002).
--
-- Covers FR-ASMT-001 (weighted scoring inputs) and FR-ASMT-002 (a persisted,
-- versioned assessment record). Decisions are computed by AssessmentService
-- and only the resulting record is stored here — the BAAF GATES themselves are
-- enforced in code (fail-closed) and never trusted to the row.
--
-- Idempotent: re-applied before every test. CREATE TABLE IF NOT EXISTS, DROP
-- COLUMN restrictions avoided, no bare seed data.

CREATE TABLE IF NOT EXISTS assessments (
  id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
  tenant_id       INT UNSIGNED NOT NULL,
  title           VARCHAR(255) NOT NULL,
  disposition     VARCHAR(32)  NOT NULL,                -- go | pilot | no-go
  composite_score DECIMAL(5,4) NOT NULL DEFAULT 0.0000,
  report_json     JSON         NULL,                    -- FR-ASMT-002 payload
  schema_version  VARCHAR(16)  NOT NULL DEFAULT '1.0',
  created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  INDEX idx_assessments_tenant (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
