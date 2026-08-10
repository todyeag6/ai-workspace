-- © AI WebScapes 2026
-- Migration 017_security_evidence: the immutable evidence store for a scan run
-- (P3-T4, SFR-EVID-001/002, SFR-SELF-004).
--
-- WHY AN EVIDENCE TABLE AND NOT A COLUMN ON security_scans. SFR-EVID-001
-- requires each item of evidence to carry scanner/version, target, timestamp,
-- request category, response metadata, reproduction and a cryptographic hash -
-- a list, not a single value, and a scan produces many of them. They are a
-- child collection of the run, and a collection needs its own table so a scan
-- can hold zero, one or hundreds of evidence items without the run row
-- ballooning or the items losing their individual provenance.
--
-- WHY THE HASH IS STORED (SFR-EVID-001). An evidence item is an artifact that
-- must be tamper-EVIDENT. Storing sha256 of the canonicalized content means a
-- later reader can recompute and detect any change - the hash is the thing
-- that makes "this is the evidence we collected" a verifiable claim rather
-- than an assertion. It is NOT the secret; only the digest travels.
--
-- WHY REDACTION IS A COLUMN, NOT A PROCESS. SFR-EVID-002 says secrets, session
-- identifiers, personal data and unnecessary response bodies shall be redacted
-- BEFORE routine display. redacted_at records WHEN the redactions were applied
-- (or null when the item never needed any), and redaction_fingerprints keeps a
-- one-way record of WHAT kinds were found and removed, so a report can say
-- "this artifact had a credential redacted" without the credential itself
-- ever leaving the store in clear form.
--
-- WHY scanner/version LIVE ON THE ROW. SFR-SELF-002 pins scanner versions, and
-- SFR-EVID-001 demands the evidence name the tool that produced it. Carrying
-- them on the evidence row means an artifact remains attributable to an exact
-- build even after the adapter that ran it has been version-bumped away.
--
-- WHY response_metadata AND reproduction ARE JSON. SFR-EVID-001 names both a
-- "response metadata" and a "reproduction" step; both are structured, and JSON
-- keeps them queryable-by-key without a schema migration every time a scanner
-- adds a field. They are deliberately separate: reproduction is the
-- re-runnable recipe, response_metadata is what the target actually returned.
--
-- IDEMPOTENCY CONTRACT (identical to 000..016): CREATE TABLE IF NOT EXISTS
-- only, no ALTER, no DROP, no trigger, no DELIMITER block, and no semicolon
-- inside a comment or string literal. tests/TestCase.php re-applies this file
-- per process, so it must be re-entrant.
--
-- tenant_id is carried for the same AC-001 reason as every other client table:
-- App\Data\TenantRepository scopes every statement by it.

CREATE TABLE IF NOT EXISTS security_evidence (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  -- Which run this evidence belongs to. The child end of the evidence<->scan
  -- link; a scan physically cannot have evidence from another tenant because
  -- tenant_id is bound by the repository, not supplied by the caller.
  scan_id BIGINT UNSIGNED NOT NULL,
  -- Optional link to the inventory row the evidence concerns (SFR-ASSET-001
  -- cross-reference). Nullable because some evidence (e.g. a connection
  -- failure) describes the RUN, not a specific asset.
  asset_id BIGINT UNSIGNED NULL,
  -- SFR-SELF-002 + SFR-EVID-001: the exact tool and build that produced this.
  scanner VARCHAR(128) NOT NULL,
  scanner_version VARCHAR(64) NOT NULL,
  target VARCHAR(512) NOT NULL,
  -- UTC, written by the application so it compares against the scan window.
  captured_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  -- SFR-EVID-001: the category of request this evidence answers (e.g.
  -- "port-scan", "auth-probe", "response-headers"). A controlled vocabulary,
  -- stored as text so an unknown category is recorded rather than refused.
  request_category VARCHAR(128) NOT NULL DEFAULT 'uncategorized',
  -- SFR-EVID-001: structured response metadata - what the target returned.
  response_metadata JSON NULL,
  -- SFR-EVID-001: the recipe to reproduce this observation.
  reproduction JSON NULL,
  -- SFR-EVID-001: the tamper-evident digest of the canonicalized evidence.
  content_hash VARCHAR(64) NOT NULL,
  -- SFR-EVID-002: the one-way record of WHAT kinds of sensitive data were
  -- redacted. Never the values themselves.
  redaction_fingerprints JSON NULL,
  -- Null until the item was cleared of secrets/PII/session tokens. A NULL here
  -- on a freshly stored row means it was safe as submitted; a timestamp means
  -- the processor scrubbed it first.
  redacted_at TIMESTAMP NULL,
  KEY idx_ev_tenant (tenant_id),
  KEY idx_ev_scan (scan_id),
  KEY idx_ev_asset (asset_id),
  KEY idx_ev_hash (tenant_id, content_hash),
  KEY idx_ev_category (tenant_id, request_category),
  CONSTRAINT fk_ev_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_ev_scan FOREIGN KEY (scan_id) REFERENCES security_scans(id),
  CONSTRAINT fk_ev_asset FOREIGN KEY (asset_id) REFERENCES security_assets(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
