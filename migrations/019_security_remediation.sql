-- © AI WebScapes 2026
-- Migration 019_security_remediation: the Remediation Tracker (P3-T7).
--
-- FRD section 2 gives this component its job list verbatim: "Status, owner,
-- comments, exceptions, due dates, retest." FRD section 4 names three of the
-- four entities below as first-class -- remediations (owner, plan, due, change
-- reference, status), risk_acceptances (approver, rationale, controls, expiry)
-- and retests (profile, result, linked finding). remediation_comments carries
-- the "comments" the component list names but the data model leaves implicit.
--
-- THE ONE THING THIS SCHEMA EXISTS TO MAKE STRUCTURAL
-- ---------------------------------------------------
-- FRD section 7, the Retest acceptance test: "Closure requires passing
-- evidence linked to remediation." Note the three conjunctions in that
-- sentence -- passing, evidence, AND linked to remediation. A schema where
-- closure is just a status column satisfies none of them, because the closing
-- caller supplies the claim and the claim is the proof. So the retest row
-- carries all three as columns that cannot be null when the result is a pass:
-- result, evidence_id/evidence_hash, and remediation_id. The tracker then
-- refuses closure unless such a row exists. The requirement becomes a query,
-- not a promise.
--
-- WHY REMEDIATION IS A SEPARATE TABLE FROM security_findings
-- -----------------------------------------------------------
-- security_findings.remediation (018) is the TEXT guidance -- what should be
-- done. This table is the WORK -- who owns it, by when, under which change
-- reference, and how far along it is. Collapsing them would mean a finding row
-- carrying two different tenses of the same word, and would give the fix no
-- identity for a retest to link to. SFR-RETEST-001 requires a retest to link
-- to the original finding AND the remediation, so the remediation has to be
-- something a foreign key can point at.
--
-- WHY EXACTLY ONE REMEDIATION PER FINDING (the UNIQUE key). A finding is a
-- deduplicated ISSUE (018). "How are we fixing this issue" has one answer at a
-- time -- if a fix fails its retest the same remediation goes back to
-- in_progress and the failed retest stays in history, which is a truer record
-- than a pile of abandoned sibling plans with no way to say which was live.
-- The append-only children (comments, retests) carry the history.
--
-- WHY risk_acceptances CARRIES BOTH review_at AND expires_at. SBR-5.3: "Risk
-- acceptance shall name approver, rationale, compensating control, review
-- date, and expiry." Five things, five columns, all NOT NULL except the
-- revocation pair. They are separate because they answer different questions:
-- review_at is when someone must LOOK at it again, expires_at is when it stops
-- being true. An acceptance with no expiry is a silent permanent waiver, which
-- is the failure mode this requirement exists to prevent -- so the column is
-- NOT NULL and the application refuses to invent one.
--
-- WHY retests RECORDS THE PROFILE VERSION AND NOT JUST THE PROFILE ID.
-- SFR-RETEST-001 requires a "defined subset/profile", and SFR-SCAN-001 makes
-- profiles versioned and immutable once used. Recording the version alongside
-- the id means a report can state the exact envelope the retest ran under even
-- after a later version exists, matching how security_scans (015) already
-- pins profile_version.
--
-- IDEMPOTENCY CONTRACT (identical to 000..018): CREATE TABLE IF NOT EXISTS
-- only, no ALTER, no DROP, no trigger, no DELIMITER block, and no semicolon
-- inside a comment or string literal. tests/TestCase.php re-applies this file
-- per process, so it must be re-entrant.
--
-- tenant_id is carried for the same AC-001 reason as every other client table:
-- App\Data\TenantRepository scopes every statement by it.

CREATE TABLE IF NOT EXISTS remediations (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  -- The issue being fixed. One plan per finding, enforced below.
  finding_id BIGINT UNSIGNED NOT NULL,
  -- FRD section 4 "owner". Who is accountable for the fix. Distinct from
  -- security_findings.owner, which is who owns the FINDING -- commonly the
  -- same person, but the fix may be handed to a different team without
  -- reassigning the finding.
  owner VARCHAR(255) NOT NULL DEFAULT '',
  -- FRD section 4 "plan". The human's stated remediation approach.
  plan TEXT NULL,
  -- FRD section 4 "due". Seeded from the finding's SLA (018 sla_due_at, itself
  -- derived from the ratified config/security/FINDING_SLA.php) so the fix
  -- inherits the deadline the finding already committed to, rather than
  -- letting a second, looser date appear beside it. Nullable only for
  -- informational findings, which carry no remediation clock.
  due_at TIMESTAMP NULL,
  -- FRD section 4 "change reference". The client's change ticket / PR / CAB
  -- record. Free text because it belongs to the client's system, not ours.
  change_reference VARCHAR(255) NULL,
  -- FRD section 4 "status". planned -> in_progress -> fix_applied -> verified,
  -- with blocked and cancelled as off-ramps. The vocabulary is validated in
  -- PHP against an allowlist (AC-002).
  --
  -- 'verified' is the load-bearing value: it is NOT reachable by asserting it.
  -- App\SecurityAgent\RemediationTracker requires a passing, evidence-bearing
  -- retest linked to this row before that status can be written, which is FRD
  -- section 7's closure rule.
  status VARCHAR(32) NOT NULL DEFAULT 'planned',
  -- Who opened the plan, and who last moved it. Named humans, because
  -- SFR-AUD-001 audits assignment and SFR-AI-001 keeps machine suggestions off
  -- decision fields entirely -- there is no ai_ column in this table by design.
  created_by VARCHAR(255) NOT NULL DEFAULT '',
  -- Set only by the verification path, alongside status = verified.
  verified_by VARCHAR(255) NULL,
  verified_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  -- One live plan per finding. See the header for why this is a constraint
  -- rather than a convention.
  UNIQUE KEY uq_remediation_finding (tenant_id, finding_id),
  KEY idx_remediation_tenant (tenant_id),
  KEY idx_remediation_status (tenant_id, status),
  KEY idx_remediation_due (tenant_id, due_at),
  KEY idx_remediation_owner (tenant_id, owner),
  CONSTRAINT fk_remediation_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_remediation_finding FOREIGN KEY (finding_id) REFERENCES security_findings(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- FRD section 4 "risk_acceptances -- approver, rationale, controls, expiry"
-- and SBR-5.3, which adds the review date and makes all five mandatory.
--
-- WHY THIS IS NOT A STATUS ON THE FINDING. security_findings.status already
-- has 'risk_accepted' (018), but a status is a single word -- it cannot name
-- an approver, carry a rationale, or expire. SBR-5.3 requires all of those, so
-- the acceptance is a record with its own lifetime, and the finding's status
-- is the summary of it. That separation is what makes expiry meaningful: when
-- the acceptance lapses, the evidence of who accepted what and why survives.
--
-- WHY THERE IS NO UNIQUE KEY ON finding_id HERE. Unlike a remediation plan, a
-- finding can legitimately be accepted more than once over its life -- an
-- acceptance expires, is reviewed, and a fresh one is granted with a new
-- approver and rationale. Superseding them would destroy exactly the audit
-- history SBR-5.3 exists to create. The application asks for the CURRENT
-- acceptance by evaluating status and expiry against a supplied clock.
CREATE TABLE IF NOT EXISTS risk_acceptances (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  finding_id BIGINT UNSIGNED NOT NULL,
  -- SBR-5.3 "approver". NOT NULL and refused when blank: an accepted risk with
  -- no named approver is an unowned decision, which is the thing being
  -- prevented.
  approver VARCHAR(255) NOT NULL,
  -- SBR-5.3 "rationale". Why this risk is acceptable.
  rationale TEXT NOT NULL,
  -- SBR-5.3 "compensating control". What reduces the risk in the absence of a
  -- fix. NOT NULL for the same reason as approver -- "we accept it and do
  -- nothing" must be written down as a stated control, not left blank.
  compensating_control TEXT NOT NULL,
  -- SBR-5.3 "review date". When a human must look at this again.
  review_at TIMESTAMP NOT NULL,
  -- SBR-5.3 "expiry". When the acceptance stops being true. NOT NULL by
  -- design -- there is no permanent waiver.
  expires_at TIMESTAMP NOT NULL,
  -- active / revoked. Expiry is NOT a stored status: it is derived by
  -- comparing expires_at to a supplied clock, so an acceptance cannot appear
  -- live merely because no batch job has run to expire it.
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  revoked_by VARCHAR(255) NULL,
  revoked_at TIMESTAMP NULL,
  revocation_reason TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_acceptance_tenant (tenant_id),
  KEY idx_acceptance_finding (tenant_id, finding_id),
  KEY idx_acceptance_expiry (tenant_id, expires_at),
  KEY idx_acceptance_status (tenant_id, status),
  CONSTRAINT fk_acceptance_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_acceptance_finding FOREIGN KEY (finding_id) REFERENCES security_findings(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- FRD section 4 "retests -- profile, result, linked finding" and
-- SFR-RETEST-001: "Retests shall use a defined subset/profile and link results
-- to the original finding and remediation."
--
-- THIS TABLE IS THE CLOSURE EVIDENCE. FRD section 7 requires closure to rest
-- on passing evidence linked to remediation, so every clause of that sentence
-- is a column here and the tracker reads them rather than trusting a caller.
--
-- WHY A FAILED RETEST IS STORED, NOT DISCARDED. A retest that failed is the
-- record that a fix was claimed and did not hold. Deleting it would let a
-- second attempt present itself as the first, and would make BRD section 7's
-- "retest closure rate" measure flattering rather than true. Like
-- finding_occurrences (018), this table has no update or delete path in the
-- application -- a retest result is a historical fact.
CREATE TABLE IF NOT EXISTS retests (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  -- SFR-RETEST-001 "link results to the original finding".
  finding_id BIGINT UNSIGNED NOT NULL,
  -- SFR-RETEST-001 "and remediation". NOT NULL -- a retest of nothing in
  -- particular cannot close anything, and FRD section 7 says the evidence must
  -- be LINKED to the remediation.
  remediation_id BIGINT UNSIGNED NOT NULL,
  -- SFR-RETEST-001 "a defined subset/profile" -- which envelope was re-run.
  scan_profile_id BIGINT UNSIGNED NOT NULL,
  -- Pinned alongside the id because profiles are versioned and immutable once
  -- used (SFR-SCAN-001), exactly as security_scans does.
  profile_version INT UNSIGNED NOT NULL DEFAULT 1,
  -- The run that produced the result, when one exists. Nullable because a
  -- retest may be an authorized manual verification rather than an automated
  -- scan, and forcing a synthetic scan row would corrupt the scan record.
  scan_id BIGINT UNSIGNED NULL,
  -- pass / fail / inconclusive, validated in PHP against an allowlist
  -- (AC-002). 'inconclusive' exists because SFR-SCAN-003 forbids reading a
  -- tool failure as a statement about the target -- a retest that could not be
  -- completed must not be recordable as a pass OR as a fail.
  result VARCHAR(16) NOT NULL,
  -- The evidence backing this result (P3-T4 security_evidence). Required by
  -- the application for a PASS, because FRD section 7 says closure requires
  -- passing EVIDENCE -- a bare assertion of success is what this column
  -- exists to refuse. Nullable at the schema level so a fail or an
  -- inconclusive result can be recorded when there is no artifact to store.
  evidence_id BIGINT UNSIGNED NULL,
  -- Carried denormalised so the retest stays meaningful after the evidence row
  -- is purged under retention (SFR-SELF-004), matching finding_occurrences.
  evidence_hash CHAR(64) NULL,
  -- The human accountable for the verification. A retest is a claim that
  -- something is fixed, and SFR-AI-001 reserves that class of judgement for a
  -- named person.
  performed_by VARCHAR(255) NOT NULL,
  performed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  note TEXT NULL,
  KEY idx_retest_tenant (tenant_id),
  KEY idx_retest_finding (tenant_id, finding_id),
  KEY idx_retest_remediation (tenant_id, remediation_id),
  KEY idx_retest_result (tenant_id, result),
  KEY idx_retest_evidence (evidence_id),
  CONSTRAINT fk_retest_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_retest_finding FOREIGN KEY (finding_id) REFERENCES security_findings(id),
  CONSTRAINT fk_retest_remediation FOREIGN KEY (remediation_id) REFERENCES remediations(id),
  CONSTRAINT fk_retest_profile FOREIGN KEY (scan_profile_id) REFERENCES scan_profiles(id),
  CONSTRAINT fk_retest_scan FOREIGN KEY (scan_id) REFERENCES security_scans(id),
  CONSTRAINT fk_retest_evidence FOREIGN KEY (evidence_id) REFERENCES security_evidence(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- FRD section 2 lists "comments" among the Remediation Tracker's
-- responsibilities. Append-only, for the same reason as finding_occurrences:
-- a discussion thread that can be edited after the fact is not a record of
-- what was said when a decision was taken.
--
-- WHY THE BODY IS PLAIN TEXT AND CALLER-REDACTED. Comments are written by
-- humans about findings, so they can contain exactly the material SFR-EVID-002
-- requires to be redacted before routine display. The application caps the
-- length and the reporting layer escapes on output -- this column stores what
-- it was given, and no display path renders it raw.
CREATE TABLE IF NOT EXISTS remediation_comments (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  remediation_id BIGINT UNSIGNED NOT NULL,
  -- Denormalised so a finding-centric view can read the thread without
  -- joining through the remediation, and so the comment survives as evidence
  -- of discussion about that finding.
  finding_id BIGINT UNSIGNED NOT NULL,
  author VARCHAR(255) NOT NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_comment_tenant (tenant_id),
  KEY idx_comment_remediation (tenant_id, remediation_id),
  KEY idx_comment_finding (tenant_id, finding_id),
  CONSTRAINT fk_comment_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_comment_remediation FOREIGN KEY (remediation_id) REFERENCES remediations(id),
  CONSTRAINT fk_comment_finding FOREIGN KEY (finding_id) REFERENCES security_findings(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
