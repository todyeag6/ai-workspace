-- © AI WebScapes 2026
-- Migration 000_baseline: the schema the platform starts from.
--
-- Source of truth: legacy/schema.sql (demo_requests, users), plus the
-- schema_migrations ledger that scripts/migrate.php writes to.
--
-- IDEMPOTENCY CONTRACT - every statement in this file MUST be re-entrant.
-- tests/TestCase.php re-applies every migrations/*.sql file before EVERY
-- single test, without consulting schema_migrations, so a statement that
-- throws on its second execution breaks the whole suite from test 2 onward.
-- Rules honoured here:
--   1. CREATE TABLE is always CREATE TABLE IF NOT EXISTS.
--   2. Indexes are declared INLINE in the CREATE TABLE - MySQL has no
--      CREATE INDEX IF NOT EXISTS, so a standalone CREATE INDEX would fail
--      with "Duplicate key name" on re-apply.
--   3. No ALTER TABLE ADD COLUMN - MySQL has no ADD COLUMN IF NOT EXISTS.
--      Every column is declared in the initial CREATE TABLE instead.
--   4. No seed INSERTs - the baseline is schema only, so there is nothing
--      that could raise "Duplicate entry" on re-apply.
--   5. No DROP statements are needed here - any future one must use IF EXISTS.
--   6. Ordering comes from the filename prefix alone (000_, 001_, ...).
--      This file must not depend on anything applied before it.
--   7. schema_migrations is created with IF NOT EXISTS like every other table.
--
-- PARSER NOTE: both tests/TestCase.php and scripts/migrate.php split this
-- file on the semicolon character. No semicolon may therefore appear inside
-- a comment or a string literal in any migration file until a real SQL
-- parser lands. This very comment broke the suite once - do not reintroduce.

CREATE TABLE IF NOT EXISTS demo_requests (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(190) NOT NULL,
  company VARCHAR(160) DEFAULT NULL,
  role_title VARCHAR(120) DEFAULT NULL,
  phone VARCHAR(40) DEFAULT NULL,
  automation_need TEXT NOT NULL,
  preferred_contact VARCHAR(30) NOT NULL DEFAULT 'email',
  ip_hash CHAR(64) DEFAULT NULL,
  user_agent VARCHAR(255) DEFAULT NULL,
  status ENUM('new', 'reviewed', 'contacted', 'closed') NOT NULL DEFAULT 'new',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_demo_requests_email (email),
  INDEX idx_demo_requests_status (status),
  INDEX idx_demo_requests_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(190) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin', 'manager', 'viewer') NOT NULL DEFAULT 'viewer',
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  last_login_at TIMESTAMP NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_users_role (role),
  INDEX idx_users_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Ledger of applied migrations, written by scripts/migrate.php.
-- version is the migration filename, which makes the PRIMARY KEY the natural
-- de-duplication mechanism for INSERT IGNORE on re-run.
CREATE TABLE IF NOT EXISTS schema_migrations (
  version VARCHAR(255) NOT NULL PRIMARY KEY,
  applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
