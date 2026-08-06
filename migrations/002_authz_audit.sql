-- © AI WebScapes 2026
-- Migration 002_authz_audit: authorisation grants, audit trail and password
-- reset tokens.
--
-- Covers FR-AUD-001 (auditable login outcome and authorisation denial),
-- SEC-005 / AC-001 (deny-by-default RBAC, cross-tenant reads impossible) and
-- the single-use password reset tokens required by P1-T4.
--
-- IDEMPOTENCY CONTRACT - identical to 000 and 001. tests/TestCase.php
-- re-applies every migrations/*.sql file, so every statement here is
-- re-entrant: CREATE TABLE IF NOT EXISTS, inline indexes, INSERT IGNORE only.
--
-- PARSER NOTE: both tests/TestCase.php and scripts/migrate.php split this file
-- on the semicolon character. No semicolon may appear inside a comment or a
-- string literal. No DELIMITER blocks, no stored procedures, no triggers.
--
-- WHY role_permissions IS A NEW TABLE: 001 created roles, permissions and
-- user_roles but nothing joining a role to the capabilities it carries, so an
-- RBAC lookup had no edge to traverse. tenant_id is carried denormalised for
-- the same reason user_roles carries it - an authorisation query filters on
-- the tenant scope without a join, and a cross-tenant grant cannot be
-- expressed by accident.

CREATE TABLE IF NOT EXISTS role_permissions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  role_id BIGINT UNSIGNED NOT NULL,
  permission_id BIGINT UNSIGNED NOT NULL,
  granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_role_permissions_tenant_role_permission (tenant_id, role_id, permission_id),
  KEY idx_role_permissions_tenant (tenant_id),
  KEY idx_role_permissions_role (role_id),
  KEY idx_role_permissions_permission (permission_id),
  CONSTRAINT fk_role_permissions_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- FR-AUD-001. outcome is an ENUM rather than free text so a query for denials
-- cannot miss rows because someone wrote 'denied ' or 'DENY'. actor_user_id is
-- NULLABLE on purpose: an anonymous request that is denied still has to leave
-- a record, and inventing a user id for it would be a lie in the audit trail.
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  actor_user_id BIGINT UNSIGNED NULL,
  event VARCHAR(64) NOT NULL,
  outcome ENUM('success', 'failure', 'denied') NOT NULL,
  object_type VARCHAR(64) NULL,
  object_id VARCHAR(64) NULL,
  detail VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_audit_log_tenant (tenant_id),
  KEY idx_audit_log_event (event),
  KEY idx_audit_log_actor (actor_user_id),
  KEY idx_audit_log_created_at (created_at),
  CONSTRAINT fk_audit_log_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Single-use password reset tokens. Only the SHA-256 of the token is stored,
-- so a database disclosure does not hand over usable reset links. used_at is
-- what makes a token single-use - the row is kept for the audit trail rather
-- than deleted on redemption.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  token_hash CHAR(64) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_password_reset_tokens_hash (token_hash),
  KEY idx_password_reset_tokens_tenant (tenant_id),
  KEY idx_password_reset_tokens_user (user_id),
  CONSTRAINT fk_password_reset_tokens_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The lead capability the P1 plan references. The leads TABLE arrives with
-- P1-T10 - a permission code is a catalogue entry, not a foreign key to a
-- table, so naming the capability early costs nothing and keeps the grant
-- seeded below identical to the one the lead feature will need.
INSERT IGNORE INTO permissions (code, name, description) VALUES
  ('lead.read', 'Read leads', 'Read lead records within the tenant');

-- STAFF ROLE RECONCILIATION (documented decision, P1-T4).
-- 001 seeds admin/manager/viewer. The plan's authorisation example uses a
-- 'staff' role holding 'lead.read'. Rather than rewrite the plan example or
-- edit migration 001, the role is seeded here idempotently for tenant 1.
INSERT IGNORE INTO roles (tenant_id, code, name, description, is_system) VALUES
  (1, 'staff', 'Staff', 'Day-to-day staff access - holds lead.read', 1);

-- Grants. Written as INSERT IGNORE ... SELECT so the permission and role ids
-- are looked up rather than hard-coded, and the UNIQUE key above makes a
-- re-apply a no-op.
INSERT IGNORE INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id FROM roles r, permissions p
WHERE r.tenant_id = 1 AND r.code = 'admin';

INSERT IGNORE INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id FROM roles r, permissions p
WHERE r.tenant_id = 1 AND r.code = 'manager'
  AND p.code IN ('tenant.view', 'user.view', 'user.manage', 'contact.manage', 'lead.read');

INSERT IGNORE INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id FROM roles r, permissions p
WHERE r.tenant_id = 1 AND r.code = 'viewer'
  AND p.code IN ('tenant.view', 'user.view');

INSERT IGNORE INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id FROM roles r, permissions p
WHERE r.tenant_id = 1 AND r.code = 'staff'
  AND p.code IN ('lead.read', 'contact.manage', 'user.view');
