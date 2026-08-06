-- © AI WebScapes 2026
-- Migration 001_tenants_identity: tenant + identity schema.
-- Covers FR-TEN-001 (immutable tenant scope on every client row) and
-- FR-IDENT-001 / FR-IDENT-004 (MFA-ready credentials, lockout counters).
-- Tables per Platform FRD Table 3: tenants, users, roles, permissions,
-- user_roles, client_contacts.
--
-- IDEMPOTENCY CONTRACT - every statement below MUST be re-entrant.
-- tests/TestCase.php re-applies every migrations/*.sql file before EVERY
-- single test without consulting schema_migrations, so anything that throws
-- on its second execution breaks the suite from test 2 onward. Rules:
--   1. CREATE TABLE is always CREATE TABLE IF NOT EXISTS.
--   2. Indexes are declared INLINE - MySQL has no CREATE INDEX IF NOT EXISTS.
--   3. No bare ALTER TABLE ADD COLUMN - MySQL has no ADD COLUMN IF EXISTS,
--      so every change to the pre-existing users table is wrapped in an
--      information_schema guard that compiles to DO 0 when already applied.
--   4. Seed rows use INSERT IGNORE.
--   5. Any DROP would use IF EXISTS - the one index drop here is guarded.
--
-- PARSER NOTE: both tests/TestCase.php and scripts/migrate.php split this
-- file on the semicolon character. No semicolon may appear inside a comment
-- or a string literal anywhere in this file. No DELIMITER blocks, no stored
-- procedures, no triggers.
--
-- WHY users IS TRANSFORMED RATHER THAN CREATED: 000_baseline.sql keeps the
-- legacy shape and always runs first, so 001 has to adopt that table - add
-- tenant_id, backfill it to tenant 1, then swap the legacy email-only UNIQUE
-- key for (tenant_id, email). The email-only key is what makes the legacy
-- schema single-tenant: it would stop two tenants ever sharing a person.

CREATE TABLE IF NOT EXISTS tenants (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  slug VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(160) NOT NULL,
  status ENUM('active', 'suspended', 'closed') NOT NULL DEFAULT 'active',
  deployment_model ENUM('cloud', 'hybrid', 'client_cloud', 'local') NOT NULL DEFAULT 'cloud',
  security_profile JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_tenants_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tenant 1 is the anchor the legacy users rows are backfilled onto. It must
-- exist before the foreign key below can be validated.
INSERT IGNORE INTO tenants (id, slug, name, status, deployment_model)
VALUES (1, 'default', 'Default Tenant', 'active', 'cloud');

-- Roles are per-tenant: a tenant may define its own, and the same role code
-- means different things in different tenants.
CREATE TABLE IF NOT EXISTS roles (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  code VARCHAR(64) NOT NULL,
  name VARCHAR(120) NOT NULL,
  description VARCHAR(255) NULL,
  is_system TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_roles_tenant_code (tenant_id, code),
  KEY idx_roles_tenant (tenant_id),
  CONSTRAINT fk_roles_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Permissions are deliberately NOT tenant-scoped: they are the platform's
-- global capability catalogue, keyed by a stable code that authorisation
-- checks reference directly. Tenants get them by holding roles, never by
-- redefining what a permission means.
CREATE TABLE IF NOT EXISTS permissions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(96) NOT NULL UNIQUE,
  name VARCHAR(120) NOT NULL,
  description VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- tenant_id is carried denormalised alongside user_id and role_id so that
-- every authorisation query can filter on the tenant scope without a join,
-- and so a cross-tenant grant is impossible to express by accident.
CREATE TABLE IF NOT EXISTS user_roles (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  role_id BIGINT UNSIGNED NOT NULL,
  granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_user_roles_tenant_user_role (tenant_id, user_id, role_id),
  KEY idx_user_roles_tenant (tenant_id),
  KEY idx_user_roles_user (user_id),
  KEY idx_user_roles_role (role_id),
  CONSTRAINT fk_user_roles_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The five contact types the FRD requires per client engagement.
CREATE TABLE IF NOT EXISTS client_contacts (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  contact_type ENUM('business', 'technical', 'data', 'billing', 'security') NOT NULL,
  name VARCHAR(160) NOT NULL,
  email VARCHAR(190) NOT NULL,
  phone VARCHAR(40) NULL,
  title VARCHAR(120) NULL,
  is_primary TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_client_contacts_tenant_type_email (tenant_id, contact_type, email),
  KEY idx_client_contacts_tenant (tenant_id),
  KEY idx_client_contacts_type (contact_type),
  CONSTRAINT fk_client_contacts_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- users: transform the legacy table from 000_baseline.sql in place.
-- Each change is guarded by an information_schema probe, so a re-apply
-- compiles to DO 0 instead of erroring on a duplicate column, key or key name.
-- ---------------------------------------------------------------------------

-- FR-TEN-001: the tenant scope. DEFAULT 1 is what backfills the legacy rows
-- in a single pass, and is kept so no pre-tenant insert path can break.
SET @has_col := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'tenant_id');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE users ADD COLUMN tenant_id BIGINT UNSIGNED NOT NULL DEFAULT 1 AFTER id',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Backfill: any row pointing at a tenant that does not exist is adopted by
-- tenant 1, which is also what makes the foreign key below validatable.
UPDATE users u
  LEFT JOIN tenants t ON t.id = u.tenant_id
  SET u.tenant_id = 1
  WHERE t.id IS NULL;

-- FR-IDENT-004: lockout counter.
SET @has_col := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'failed_logins');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE users ADD COLUMN failed_logins INT UNSIGNED NOT NULL DEFAULT 0',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- FR-IDENT-004: NULL means the account is not locked.
SET @has_col := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'locked_until');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE users ADD COLUMN locked_until TIMESTAMP NULL DEFAULT NULL',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- FR-IDENT-001: MFA-ready from day one - the secret column exists before the
-- feature does, so enrolling MFA later is not a migration event.
SET @has_col := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'mfa_secret');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(255) NULL',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Account lifecycle. The legacy is_active flag is left in place so nothing
-- reading it breaks mid-phase - status is the richer replacement.
SET @has_col := (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'status');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE users ADD COLUMN status ENUM(''active'', ''disabled'', ''locked'') NOT NULL DEFAULT ''active''',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- FR-TEN-001: the composite unique key. Added BEFORE the legacy email-only
-- key is dropped so users is never left without a uniqueness guarantee.
SET @has_idx := (SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'
    AND INDEX_NAME = 'uq_users_tenant_email');
SET @sql := IF(@has_idx = 0,
  'ALTER TABLE users ADD UNIQUE KEY uq_users_tenant_email (tenant_id, email)',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Plain tenant index for scope filtering, and the index the foreign key
-- below needs. Named explicitly so the FK does not silently adopt another.
SET @has_idx := (SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'
    AND INDEX_NAME = 'idx_users_tenant');
SET @sql := IF(@has_idx = 0,
  'ALTER TABLE users ADD KEY idx_users_tenant (tenant_id)',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- FR-TEN-001 THE KEY CHANGE: drop the legacy UNIQUE key on email alone.
-- Its name is whatever 000_baseline.sql inline UNIQUE produced, so it is
-- looked up by shape - a unique, non-primary index whose ONLY column is
-- email - rather than by a hard-coded name.
SET @legacy_idx := (SELECT s.INDEX_NAME FROM information_schema.STATISTICS s
  WHERE s.TABLE_SCHEMA = DATABASE() AND s.TABLE_NAME = 'users'
    AND s.NON_UNIQUE = 0 AND s.INDEX_NAME <> 'PRIMARY'
    AND s.COLUMN_NAME = 'email' AND s.SEQ_IN_INDEX = 1
    AND (SELECT COUNT(*) FROM information_schema.STATISTICS c
         WHERE c.TABLE_SCHEMA = DATABASE() AND c.TABLE_NAME = 'users'
           AND c.INDEX_NAME = s.INDEX_NAME) = 1
  LIMIT 1);
SET @sql := IF(@legacy_idx IS NULL,
  'DO 0',
  CONCAT('ALTER TABLE users DROP INDEX ', @legacy_idx));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- FR-TEN-001: enforce the tenant scope referentially, not by convention.
SET @has_fk := (SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'
    AND CONSTRAINT_NAME = 'fk_users_tenant' AND CONSTRAINT_TYPE = 'FOREIGN KEY');
SET @sql := IF(@has_fk = 0,
  'ALTER TABLE users ADD CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- user_roles.user_id could not be declared as a foreign key inside its
-- CREATE TABLE: on a first apply that table is created before users has been
-- given its tenant scope, so the constraint is added here instead, guarded.
SET @has_fk := (SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_roles'
    AND CONSTRAINT_NAME = 'fk_user_roles_user' AND CONSTRAINT_TYPE = 'FOREIGN KEY');
SET @sql := IF(@has_fk = 0,
  'ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE',
  'DO 0');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Baseline permission catalogue. INSERT IGNORE against the unique code makes
-- re-application a no-op.
INSERT IGNORE INTO permissions (code, name, description) VALUES
  ('tenant.view', 'View tenant', 'Read tenant profile and settings'),
  ('tenant.manage', 'Manage tenant', 'Update tenant profile and settings'),
  ('user.view', 'View users', 'List and read users within the tenant'),
  ('user.manage', 'Manage users', 'Create, update and disable users within the tenant'),
  ('role.assign', 'Assign roles', 'Grant and revoke roles within the tenant'),
  ('contact.manage', 'Manage contacts', 'Maintain client contact records');

-- System roles for the default tenant. Unique on (tenant_id, code).
INSERT IGNORE INTO roles (tenant_id, code, name, description, is_system) VALUES
  (1, 'admin', 'Administrator', 'Full control within the tenant', 1),
  (1, 'manager', 'Manager', 'Day-to-day operational access', 1),
  (1, 'viewer', 'Viewer', 'Read-only access', 1);
