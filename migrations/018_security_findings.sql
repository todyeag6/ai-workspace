-- © AI WebScapes 2026
-- Migration 018_security_findings: the deduplicated finding record and its
-- occurrence history (P3-T5, SFR-FIND-001, SFR-FIND-002, SFR-AI-001,
-- SFR-AUD-001).
--
-- WHY TWO TABLES AND NOT ONE. SFR-FIND-002 requires repeated evidence to
-- update occurrence history WITHOUT destroying previous state. One table
-- cannot do that: a second sighting of the same issue would either overwrite
-- the first row (history destroyed) or insert a twin (the finding is no longer
-- one thing anyone can assign, close or report on). Splitting them makes the
-- guarantee structural - security_findings holds the STABLE identity a human
-- owns and closes, finding_occurrences holds the append-only list of times it
-- was observed. Closing a finding never deletes an occurrence, and a new
-- occurrence never rewrites the finding's status.
--
-- WHY THE FINGERPRINT IS UNIQUE PER TENANT. SFR-FIND-001 requires findings to
-- have a UNIQUE fingerprint. The uniqueness constraint is what makes
-- deduplication a property of the SCHEMA rather than of whichever code path
-- happened to run: two scans producing the same issue physically cannot create
-- two findings, so the second one is forced down the "append an occurrence"
-- path. Scoped by tenant_id because two clients may legitimately have the same
-- issue on the same software and they are not the same finding (AC-001).
--
-- WHY EVERY SFR-FIND-001 FIELD IS A COLUMN. The requirement enumerates:
-- unique fingerprint, title, category, severity, confidence, affected assets,
-- evidence, remediation, standards mapping, owner, status, SLA and history.
-- Each is a column (or, for the inherently multi-valued ones, a JSON column or
-- the occurrence table), so a report cannot omit one by forgetting to join and
-- an ingest cannot invent one. affected_assets and standards_mapping are JSON
-- because they are lists whose length is not known in advance; making them
-- child tables would buy queryability the reporting layer does not need yet
-- and would let a finding exist with an empty mapping through a missing insert
-- rather than a visible empty array.
--
-- WHY STATUS AND SEVERITY CARRY AN AI PROVENANCE FLAG (SFR-AI-001). AI may
-- summarize and suggest severity/remediation but shall NOT alter confirmed
-- status, close findings, or authorize risk acceptance without a human
-- decision. That is enforced in App\SecurityAgent\FindingRepository, but the
-- schema has to be able to REPRESENT the distinction or the rule has nothing
-- to write down: ai_suggested_severity / ai_suggested_remediation hold the
-- machine's opinion in fields that are NOT the authoritative severity /
-- remediation, and confirmed_by / confirmed_at name the human who made the
-- call. An AI suggestion therefore lands beside the decision, never on it.
--
-- WHY SLA IS A DUE DATE PLUS A CLOCK-START AND NOT A DURATION. "SLA" in
-- SFR-FIND-001 has to survive a severity change: sla_due_at is recomputed from
-- first_seen_at when severity is revised by a human, so the record always
-- answers "by when must this be fixed" directly rather than requiring the
-- reader to re-derive it from a policy that may since have changed.
--
-- IDEMPOTENCY CONTRACT (identical to 000..017): CREATE TABLE IF NOT EXISTS
-- only, no ALTER, no DROP, no trigger, no DELIMITER block, and no semicolon
-- inside a comment or string literal. tests/TestCase.php re-applies this file
-- per process, so it must be re-entrant.
--
-- tenant_id is carried for the same AC-001 reason as every other client table:
-- App\Data\TenantRepository scopes every statement by it.

CREATE TABLE IF NOT EXISTS security_findings (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  -- SFR-FIND-001: the unique fingerprint. A deterministic digest of the
  -- issue's identity (category + canonical asset + the normalised signature of
  -- what was observed), computed by FindingEngine. It is what makes the second
  -- sighting recognisable as the same finding.
  fingerprint CHAR(64) NOT NULL,
  title VARCHAR(255) NOT NULL,
  -- The scan category vocabulary from FRD section 5 (transport-and-exposure,
  -- http-configuration, content-exposure, authentication-session,
  -- authorization-api, input-handling, dependencies, ai-security,
  -- operational-controls). Stored as text so an unrecognised category is
  -- recorded rather than silently dropped, and validated in PHP.
  category VARCHAR(64) NOT NULL,
  -- The AUTHORITATIVE severity. BRD section 5: "Automated severity is advisory
  -- until validated according to the service plan", so the engine's computed
  -- score lands in ai_suggested_severity and only a human decision writes
  -- THIS column (SFR-AI-001).
  severity VARCHAR(16) NOT NULL DEFAULT 'informational',
  -- EVIDENCE confidence, in the sense BRD section 5 uses it when it lists
  -- "evidence confidence" among the inputs to severity: how much the artifact
  -- supports the claim. Deliberately the same low/medium/high vocabulary
  -- security_assets.confidence already uses, and deliberately NOT the
  -- suspected/confirmed axis - that is the finding's STATUS, and reusing the
  -- word "confirmed" for both would make SFR-AI-001's "shall not alter
  -- confirmed status" ambiguous about which column it protects.
  confidence VARCHAR(16) NOT NULL DEFAULT 'medium',
  -- SFR-FIND-001 "affected assets": a JSON list of security_assets ids. A list
  -- because one issue commonly spans several hosts, and re-observing it on a
  -- new host must widen the finding rather than fork it.
  affected_assets JSON NULL,
  -- SFR-FIND-001 "remediation": the authoritative human-owned fix guidance.
  remediation TEXT NULL,
  -- SFR-FIND-001 "standards mapping": a JSON list of standard references
  -- (e.g. OWASP ASVS / Top 10 / API / GenAI / NIST identifiers) so a
  -- compliance report can be assembled without re-classifying the finding.
  standards_mapping JSON NULL,
  -- SFR-FIND-001 "owner": who is accountable. Empty until assigned; an
  -- unassigned finding is a visible state, not a null nobody notices.
  owner VARCHAR(255) NOT NULL DEFAULT '',
  -- SFR-FIND-001 "status" + SFR-REPORT-001's vocabulary. open/confirmed are
  -- live states, risk_accepted/remediated/closed are terminal-ish states that
  -- SFR-AI-001 reserves for a human.
  status VARCHAR(32) NOT NULL DEFAULT 'open',
  -- SFR-FIND-001 "SLA". Derived from severity at first sight and recomputed
  -- when a human revises severity. Nullable only for informational findings
  -- that carry no remediation deadline.
  sla_due_at TIMESTAMP NULL,
  -- SFR-FIND-001 "history" (the scalar part; the per-sighting part is
  -- finding_occurrences). first_seen_at is written once and never moved, so a
  -- re-observation cannot make an old finding look new.
  first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  occurrence_count INT UNSIGNED NOT NULL DEFAULT 1,
  -- SFR-AI-001: the machine's non-authoritative opinion, held separately from
  -- the decision so that reading the finding never confuses the two. Writing
  -- these NEVER changes severity, remediation, status or confidence.
  ai_suggested_severity VARCHAR(16) NULL,
  ai_suggested_remediation TEXT NULL,
  ai_summary TEXT NULL,
  -- SFR-AI-001: the human who confirmed or closed. A status that requires a
  -- human decision cannot be reached with these null - the repository refuses.
  confirmed_by VARCHAR(255) NULL,
  confirmed_at TIMESTAMP NULL,
  closed_by VARCHAR(255) NULL,
  closed_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  -- Deduplication is a schema property, not a code convention (SFR-FIND-002).
  UNIQUE KEY uq_finding_fingerprint (tenant_id, fingerprint),
  KEY idx_finding_tenant (tenant_id),
  KEY idx_finding_status (tenant_id, status),
  KEY idx_finding_severity (tenant_id, severity),
  KEY idx_finding_sla (tenant_id, sla_due_at),
  CONSTRAINT fk_finding_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The append-only sighting log. One row per (finding, observation).
--
-- WHY THIS TABLE HAS NO UPDATE PATH IN THE APPLICATION. SFR-FIND-002's
-- guarantee is "without destroying previous state". An occurrence is a
-- historical fact - it was observed, at that time, by that scan, with that
-- evidence - and a fact does not get edited. FindingRepository only ever
-- INSERTs here, so the history is append-only by construction rather than by
-- everyone remembering not to overwrite it.
--
-- WHY evidence_id IS NULLABLE. Some occurrences are recorded from a scan that
-- produced no storable artifact (e.g. a configuration observation). The
-- sighting still belongs in history; forcing an evidence row would push
-- callers into inventing one.
CREATE TABLE IF NOT EXISTS finding_occurrences (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  finding_id BIGINT UNSIGNED NOT NULL,
  -- Which run observed it. The link that lets a report say "still present as
  -- of the March scan" rather than only "seen at some point".
  scan_id BIGINT UNSIGNED NOT NULL,
  -- Which asset this particular sighting concerned. Nullable for a finding
  -- that describes the engagement rather than one host.
  asset_id BIGINT UNSIGNED NULL,
  -- The evidence backing THIS sighting (P3-T4's security_evidence). Reusing
  -- the evidence row means the occurrence inherits its redaction and its
  -- content hash rather than restating them.
  evidence_id BIGINT UNSIGNED NULL,
  -- Carried denormalised so the occurrence remains meaningful even when the
  -- evidence row is later purged under retention (SFR-SELF-004).
  evidence_hash CHAR(64) NULL,
  observed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  -- What the finding's status was when this sighting landed, so the history
  -- shows "seen again while already risk-accepted" without a join to an audit
  -- trail.
  status_at_observation VARCHAR(32) NOT NULL DEFAULT 'open',
  -- Free-form, redacted-by-the-caller note. TEXT rather than JSON because it
  -- carries a human sentence, not a structure.
  note TEXT NULL,
  KEY idx_occ_tenant (tenant_id),
  KEY idx_occ_finding (tenant_id, finding_id),
  KEY idx_occ_scan (scan_id),
  KEY idx_occ_evidence (evidence_id),
  CONSTRAINT fk_occ_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_occ_finding FOREIGN KEY (finding_id) REFERENCES security_findings(id),
  CONSTRAINT fk_occ_scan FOREIGN KEY (scan_id) REFERENCES security_scans(id),
  CONSTRAINT fk_occ_asset FOREIGN KEY (asset_id) REFERENCES security_assets(id),
  CONSTRAINT fk_occ_evidence FOREIGN KEY (evidence_id) REFERENCES security_evidence(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
