-- © AI WebScapes 2026
-- Migration 020_scan_recurrence: recurring-scan support for the Scan Scheduler.
--
-- FRD section 2.36 ("Scan Scheduler") names "One-time/recurring jobs,
-- maintenance windows, concurrency, rate and safety limits" as a scheduler
-- deliverable, and SFR-AUTH-001 [Must] requires an authorization to carry a
-- "validity period ... before scheduling." The shipped security_scans table
-- (015) has no recurrence, no validity period, and no next-run anchor, so the
-- scheduler can only record a single one-shot run and cannot express a
-- recurring engagement. This migration adds the three missing columns plus a
-- policy-version tag.
--
-- WHAT THIS MIGRATION IS FOR (and what it is NOT)
-- -------------------------------------------------
-- It makes the data model able to represent a recurring scan and its validity
-- window. It introduces NO scheduling behaviour, NO worker, and NO production
-- call site. That is a deliberate scope decision: the recurrence semantics live
-- in ScanRepository / ScanScheduler (added in this change) and are unit-tested
-- in isolation. A recurring scan only becomes "live" when a future change
-- introduces a due-run worker or wires scheduleRecurring() into a production
-- path. Until then these columns simply exist and are validated.
--
-- IDEMPOTENCY CONTRACT (identical to 001, and to 000..019 for CREATE TABLE):
-- every change is guarded by an information_schema probe, so a re-apply compiles
-- to DO 0 instead of erroring on a duplicate column or key. MySQL has no
-- ADD COLUMN IF EXISTS / CREATE INDEX IF NOT EXISTS that is reliable across
-- the toolchain, so each step is conditionally prepared and executed.

-- Recurrence cadence (none = the original one-shot behaviour).
SET @has_col := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'security_scans' AND COLUMN_NAME = 'recurrence');
SET @sql := IF(@has_col = 0,
  "ALTER TABLE security_scans ADD COLUMN recurrence ENUM('none', 'daily', 'weekly', 'monthly') NOT NULL DEFAULT 'none'",
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- SFR-AUTH-001 validity period: the authorization this run was granted under
-- stops being valid after this instant. NULL means "no expiry".
SET @has_col := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'security_scans' AND COLUMN_NAME = 'valid_until');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE security_scans ADD COLUMN valid_until TIMESTAMP NULL',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- The next instant a recurrence should spawn a run. NULL for one-shot scans.
SET @has_col := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'security_scans' AND COLUMN_NAME = 'next_run_at');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE security_scans ADD COLUMN next_run_at TIMESTAMP NULL',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- The SCAN_SCHEDULE_POLICY version the recurrence was scheduled under, so a
-- later policy edit cannot retroactively change what an old recurrence meant.
SET @has_col := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'security_scans' AND COLUMN_NAME = 'recurrence_policy_version');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE security_scans ADD COLUMN recurrence_policy_version VARCHAR(32) NULL',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- The due-run query filters on next_run_at <= :now AND (valid_until IS NULL OR
-- valid_until > :now). A composite index keeps that predicate index-covered as
-- the table grows. Guarded the same way.
SET @has_idx := (SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'security_scans' AND INDEX_NAME = 'idx_sc_nextrun');
SET @sql := IF(@has_idx = 0,
  'CREATE INDEX idx_sc_nextrun ON security_scans (tenant_id, next_run_at, recurrence)',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Readable alongside the existing status index (idx_sc_status).
SET @has_idx := (SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'security_scans' AND INDEX_NAME = 'idx_sc_recurrence');
SET @sql := IF(@has_idx = 0,
  'CREATE INDEX idx_sc_recurrence ON security_scans (tenant_id, recurrence, status)',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
