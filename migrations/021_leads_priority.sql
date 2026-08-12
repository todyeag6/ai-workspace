-- © AI WebScapes 2026
-- Migration 021_leads_priority: LFR-DASH-002 lead filter dimension "priority".
-- Adds a low/normal/high priority enum to leads so the filter surface can target
-- high-value leads. DEFAULT 'normal' keeps every existing row valid (LeadService
-- does not yet set it; this is a read-side dimension only).
--
-- IDEMPOTENCY CONTRACT - tests/TestCase.php re-applies every migrations/*.sql
-- whenever the schema looks absent, so this statement must be re-entrant. MySQL
-- has no ADD COLUMN IF NOT EXISTS, so guard the ALTER with an information_schema
-- probe (same pattern as migrations/001_tenants_identity.sql:117-151). DO 0 when
-- the column already exists.
--
-- PARSER NOTE: tests/TestCase.php and scripts/migrate.php split this file on the
-- semicolon character. No semicolon may appear inside a comment or string literal.

SET @has_col := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'leads' AND COLUMN_NAME = 'priority');

SET @sql := IF(@has_col = 0,
  'ALTER TABLE leads ADD COLUMN priority ENUM(''low'', ''normal'', ''high'') NOT NULL DEFAULT ''normal'' AFTER status',
  'DO 0');

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
