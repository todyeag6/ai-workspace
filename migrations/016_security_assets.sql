-- © AI WebScapes 2026
-- Migration 016_security_assets: the versioned asset inventory the security
-- agent scans against (P3-T3, SFR-ASSET-001).
--
-- WHY AN INVENTORY TABLE AT ALL. SFR-ASSET-001 requires the agent to maintain
-- a versioned asset inventory carrying first seen, last seen, source,
-- confidence, owner, environment and criticality. Every one of those is a fact
-- about the CLIENT'S estate, not about a scan run, so it cannot live on
-- security_scans - a target seen by three scans is one asset with three
-- sightings, and a report that cannot say when an asset was first observed
-- cannot show drift.
--
-- WHY VERSION IS A COLUMN AND NOT A SEPARATE HISTORY TABLE. The requirement is
-- that the inventory be versioned and that first_seen survive re-discovery.
-- One row per (tenant, canonical_asset, asset_type) with a monotonic version
-- gives exactly that: re-seeing an asset bumps version and moves last_seen,
-- while first_seen is written once at insert and never updated again. The
-- uniqueness constraint is what makes re-discovery an UPSERT rather than a
-- duplicate row, so the inventory cannot silently grow a second copy of the
-- same host under a different id.
--
-- WHY confidence IS STORED. Discovery is inference: a host found by DNS
-- enumeration is not known with the same certainty as one supplied by the
-- client. Recording the confidence keeps an inferred asset from being reported
-- as an established one.
--
-- IDEMPOTENCY CONTRACT (identical to 000..015): CREATE TABLE IF NOT EXISTS
-- only, no ALTER, no DROP, no trigger, no DELIMITER block, and no semicolon
-- inside a comment or string literal. tests/TestCase.php re-applies this file
-- per process, so it must be re-entrant.
--
-- tenant_id is carried for the same AC-001 reason as every other client table:
-- App\Data\TenantRepository scopes every statement by it.

CREATE TABLE IF NOT EXISTS security_assets (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  -- The normalised identity of the asset (host, domain, URL, IP). Canonical
  -- so that two spellings of the same target are one inventory entry.
  canonical_asset VARCHAR(512) NOT NULL,
  asset_type VARCHAR(64) NOT NULL DEFAULT 'host',
  -- Bumped on every re-discovery: the inventory is versioned, not overwritten.
  version INT UNSIGNED NOT NULL DEFAULT 1,
  environment VARCHAR(64) NOT NULL DEFAULT 'production',
  owner VARCHAR(255) NOT NULL DEFAULT '',
  criticality VARCHAR(32) NOT NULL DEFAULT 'medium',
  -- How certain the discovery is. Defaults to medium rather than high: an
  -- asset nobody rated is not thereby confirmed.
  confidence VARCHAR(16) NOT NULL DEFAULT 'medium',
  -- Written once at insert and never moved. last_seen is written by the
  -- application in UTC on every sighting, deliberately NOT by
  -- ON UPDATE CURRENT_TIMESTAMP, so the value cannot come from the database
  -- session clock while the comparison comes from PHP.
  first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  source VARCHAR(128) NOT NULL DEFAULT 'asset-discovery',
  discovery_meta JSON NULL,
  -- Re-discovery must find the existing row rather than insert a twin.
  UNIQUE KEY uq_asset_tenant (tenant_id, canonical_asset, asset_type),
  KEY idx_asset_tenant (tenant_id),
  KEY idx_asset_canonical (canonical_asset),
  CONSTRAINT fk_asset_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
