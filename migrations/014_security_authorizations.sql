-- © AI WebScapes 2026
-- Migration 014_security_authorizations: engagement authorization + scope
-- (P3-T1, SFR-AUTH-001/002/003, SBR-3.1/3.2).
--
-- WHY THESE TWO TABLES. SBR-3.1 says a scan shall not start without recorded
-- client authorization, in-scope assets, allowed techniques, timing, contacts
-- and stop conditions. security_authorizations is that record; scan_targets is
-- the in-scope asset list it authorises. Neither is derivable from the other,
-- and neither is optional: App\SecurityAgent\ScopeManager reads BOTH before
-- every single request (SFR-AUTH-002), so a redirect to a host nobody listed
-- is refused rather than followed.
--
-- WHY CREDENTIALS LIVE HERE AS CIPHERTEXT ONLY. SFR-AUTH-003 requires scoped
-- secrets that never reach a report or a log. The plaintext column simply does
-- not exist: credentials_ciphertext holds an AES-256-GCM payload written by
-- App\SecurityAgent\ScopedSecretStore, and credentials_fingerprint holds a
-- truncated SHA-256 so a report can say WHICH credential was used without
-- being able to say what it is.
--
-- IDEMPOTENCY CONTRACT (identical to 000..013): CREATE TABLE IF NOT EXISTS
-- only, no ALTER, no DROP, no trigger, no DELIMITER block, and no semicolon
-- inside a comment or string literal. tests/TestCase.php re-applies this file
-- per process, so it must be re-entrant.
--
-- tenant_id is carried on both tables for the same AC-001 reason as every
-- other client table: App\Data\TenantRepository scopes every statement by it.

CREATE TABLE IF NOT EXISTS security_authorizations (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  client_name VARCHAR(190) NOT NULL,
  -- 'draft' is the birth status. SBR-3.2 requires verified ownership BEFORE
  -- active testing, so nothing is created 'active' - AuthorizationRepository
  -- ::activate() runs OwnershipVerifier first and refuses otherwise.
  status ENUM('draft', 'active', 'expired', 'revoked') NOT NULL DEFAULT 'draft',
  -- The validity period (SFR-AUTH-001 "validity period"). NULL means "not
  -- recorded", which the domain treats as NOT schedulable rather than as
  -- unbounded permission.
  valid_from TIMESTAMP NULL,
  valid_to TIMESTAMP NULL,
  -- The agreed technique envelope (SFR-AUTH-001 "technique profile").
  technique_profile JSON NOT NULL,
  -- Who to call to stop an active test (SFR-AUTH-001 "stop contact").
  stop_contact VARCHAR(255) NOT NULL,
  -- SBR-3.2: the approved method used to prove ownership or delegated
  -- authority, and the evidence reference for it.
  ownership_proof_type VARCHAR(64) NOT NULL,
  ownership_proof_ref VARCHAR(255) NOT NULL,
  -- SFR-AUTH-003: ciphertext only. There is deliberately no plaintext column.
  credentials_ciphertext MEDIUMTEXT NULL,
  credentials_fingerprint VARCHAR(64) NULL,
  created_by BIGINT UNSIGNED NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_auth_tenant (tenant_id, id),
  KEY idx_auth_tenant (tenant_id),
  KEY idx_auth_status (tenant_id, status),
  CONSTRAINT fk_auth_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The in-scope asset list (SBR-3.1 "in-scope assets"). raw_target keeps what
-- the client wrote, canonical_target is what SFR-AUTH-002 actually matches on
-- so that scheme case, default ports and fragments cannot smuggle a target
-- past the check. excluded=1 is an explicit carve-out INSIDE an otherwise
-- in-scope estate and is refused like anything unlisted.
CREATE TABLE IF NOT EXISTS scan_targets (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  authorization_id BIGINT UNSIGNED NOT NULL,
  raw_target VARCHAR(512) NOT NULL,
  canonical_target VARCHAR(512) NOT NULL,
  in_scope TINYINT(1) NOT NULL DEFAULT 1,
  excluded TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_st_tenant (tenant_id),
  KEY idx_st_lookup (tenant_id, authorization_id),
  CONSTRAINT fk_st_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_st_auth FOREIGN KEY (authorization_id) REFERENCES security_authorizations(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
