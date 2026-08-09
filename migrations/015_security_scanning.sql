-- © AI WebScapes 2026
-- Migration 015_security_scanning: scan profiles, scan runs and the safety
-- event trail (P3-T2, SFR-SAFE-001/002/003, SBR-3.3/3.5).
--
-- WHY THESE THREE TABLES. SFR-SAFE-001 requires that EVERY scan enforce
-- concurrency, request rate, timeout, payload size, retry and duration limits.
-- A limit that lives in application configuration is a limit that differs
-- between deployments and cannot be shown to a client after the fact, so the
-- approved envelope is stored per profile (scan_profiles) and the live counters
-- are stored per run (security_scans). scan_events is the evidence: SFR-SAFE-002
-- and SBR-3.5 require an automatic stop, and the P3 exit-gate tests require the
-- stop to be OBSERVABLE, not merely effective.
--
-- WHY THE COUNTERS LIVE IN THE DATABASE AND NOT IN PROCESS MEMORY. The kill
-- switch has to reach a scan the operator is not sharing a process with, and
-- the rate window has to survive a worker restart. An in-memory counter would
-- reset on restart and silently re-grant the whole allowance, which is exactly
-- the "observed requests exceed the approved profile" failure the acceptance
-- test forbids.
--
-- WHY destructive_checks_enabled AND destructive_approved ARE TWO COLUMNS.
-- SFR-SAFE-003 says destructive checks are disabled by default AND require a
-- separately approved profile. One boolean cannot express "someone asked for
-- this" and "someone with authority signed it off" at the same time; two can,
-- and App\SecurityAgent\SafetyMonitor refuses unless BOTH are set.
--
-- IDEMPOTENCY CONTRACT (identical to 000..014): CREATE TABLE IF NOT EXISTS
-- only, no ALTER, no DROP, no trigger, no DELIMITER block, and no semicolon
-- inside a comment or string literal. tests/TestCase.php re-applies this file
-- per process, so it must be re-entrant.
--
-- tenant_id is carried on all three tables for the same AC-001 reason as every
-- other client table: App\Data\TenantRepository scopes every statement by it.

CREATE TABLE IF NOT EXISTS scan_profiles (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  authorization_id BIGINT UNSIGNED NOT NULL,
  -- A profile is versioned rather than edited in place: a completed scan must
  -- always be able to name the exact envelope it ran under (SFR-SCAN-001).
  version INT UNSIGNED NOT NULL DEFAULT 1,
  checks JSON NOT NULL,
  -- SFR-SAFE-003. Default 0 is the requirement, not a convenience: a profile
  -- created by a caller that says nothing about destructive checks is
  -- non-destructive (SBR-3.3).
  destructive_checks_enabled TINYINT(1) NOT NULL DEFAULT 0,
  -- The separate approval. Set only by an explicit approval act, which is
  -- audited - see ScanProfileRepository::approveDestructiveChecks().
  destructive_approved TINYINT(1) NOT NULL DEFAULT 0,
  -- The six limits of SFR-SAFE-001, with conservative defaults so an
  -- unspecified profile is still a safe profile (SBR-3.3).
  concurrency_limit INT UNSIGNED NOT NULL DEFAULT 1,
  rate_limit_per_min INT UNSIGNED NOT NULL DEFAULT 60,
  request_timeout_sec INT UNSIGNED NOT NULL DEFAULT 30,
  max_payload_bytes INT UNSIGNED NOT NULL DEFAULT 1048576,
  max_retries INT UNSIGNED NOT NULL DEFAULT 3,
  max_duration_sec INT UNSIGNED NOT NULL DEFAULT 3600,
  -- Once a scan has run under this profile the envelope is frozen, so the
  -- report cannot be re-interpreted by editing the profile afterwards.
  immutable_after_use TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_sp_tenant (tenant_id, id),
  KEY idx_sp_tenant (tenant_id),
  KEY idx_sp_auth (authorization_id),
  CONSTRAINT fk_sp_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_sp_auth FOREIGN KEY (authorization_id) REFERENCES security_authorizations(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One scan run. profile_version is COPIED rather than joined: the run records
-- which version of the envelope it was granted, so a later profile version
-- cannot retroactively widen what an old scan is understood to have done.
--
-- kill_requested is a plain flag and not a status value on purpose. The
-- operator's request and the scan's own lifecycle are different facts: a
-- request arriving while the scan is mid-request must be visible to the next
-- poll (SFR-SAFE-002 "immediate") without waiting for a status transition that
-- only the scanner itself can make.
CREATE TABLE IF NOT EXISTS security_scans (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  authorization_id BIGINT UNSIGNED NOT NULL,
  scan_profile_id BIGINT UNSIGNED NOT NULL,
  profile_version INT UNSIGNED NOT NULL,
  status ENUM('scheduled', 'running', 'paused', 'stopped', 'completed', 'failed')
    NOT NULL DEFAULT 'scheduled',
  kill_requested TINYINT(1) NOT NULL DEFAULT 0,
  -- Live counters for the fixed rate window and the concurrency ceiling.
  observed_requests INT UNSIGNED NOT NULL DEFAULT 0,
  active_concurrency INT UNSIGNED NOT NULL DEFAULT 0,
  rate_window_start TIMESTAMP NULL,
  started_at TIMESTAMP NULL,
  stopped_at TIMESTAMP NULL,
  scheduled_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_sc_tenant (tenant_id),
  KEY idx_sc_auth (authorization_id),
  KEY idx_sc_profile (scan_profile_id),
  KEY idx_sc_status (tenant_id, status),
  CONSTRAINT fk_sc_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The safety trail. Every refusal, pause and automatic stop writes a row here
-- BEFORE the verdict is returned to the caller, so there is no code path that
-- refuses silently and no acceptance test that has to infer a stop from an
-- absence of requests.
CREATE TABLE IF NOT EXISTS scan_events (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  scan_id BIGINT UNSIGNED NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  detail TEXT NULL,
  occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_se_tenant (tenant_id),
  KEY idx_se_scan (scan_id),
  KEY idx_se_lookup (tenant_id, scan_id, event_type),
  CONSTRAINT fk_se_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_se_scan FOREIGN KEY (scan_id) REFERENCES security_scans(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
