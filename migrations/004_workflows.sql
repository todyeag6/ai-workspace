-- © AI WebScapes 2026
-- Migration 004_workflows: durable state for the workflow orchestrator (P1-T9).
--
-- Covers FR-ORCH-001 (a failed step must be able to find what it has to undo),
-- FR-ORCH-002 (the idempotency key a run claimed is recorded, not only held in
-- Redis) and FR-ORCH-003 (a high-impact step runs only once a HUMAN approver
-- id exists - the orchestration-level form of FR-AI-006).
--
-- IDEMPOTENCY CONTRACT - identical to 000, 001, 002_agents, 002_authz_audit
-- and 003_tools. tests/TestCase.php re-applies every migrations/*.sql file, so
-- every statement here is re-entrant: CREATE TABLE IF NOT EXISTS, inline
-- indexes, INSERT IGNORE only. No ALTER, no DROP.
--
-- PARSER NOTE: both tests/TestCase.php and scripts/migrate.php split this file
-- on the semicolon character. No semicolon may appear inside a comment or a
-- string literal. No DELIMITER blocks, no stored procedures, no triggers.

-- One row per attempt to execute a workflow, including the attempts that did
-- nothing because every step was a replay. WHY RECORD THOSE: "the retry was
-- effect-free" is a claim an operator has to be able to check after the fact,
-- and a run table that only holds successful runs cannot answer it.
--
-- idempotency_key is the CALLER's key when one was supplied and a deterministic
-- derivation of workflow plus step shape when it was not, so an unkeyed retry
-- of an identical run is still a replay rather than a second charge.
--
-- approver_id is denormalised from workflow_approvals on purpose: it is the
-- authority THIS run acted under, and it must stay true in the audit trail even
-- if the approval is later revoked.
CREATE TABLE IF NOT EXISTS workflow_runs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  workflow_id VARCHAR(120) NOT NULL,
  idempotency_key VARCHAR(191) NULL,
  status ENUM('running', 'completed', 'awaiting_approval', 'compensated', 'failed')
    NOT NULL DEFAULT 'running',
  approver_id BIGINT UNSIGNED NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_workflow_runs_workflow (workflow_id),
  KEY idx_workflow_runs_key (idempotency_key),
  KEY idx_workflow_runs_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- FR-ORCH-003. The presence of a row here is the ONLY thing that lets a high or
-- critical step execute. approver_id is a human user id: there is deliberately
-- no "system" or "auto" sentinel, because the moment one exists the gate can be
-- satisfied by the thing it is supposed to constrain (SEC-010, FR-AI-006).
--
-- UNIQUE on workflow_id: one standing approval per workflow, re-approval
-- updates the approver rather than accumulating rows that make "who signed
-- this off?" ambiguous.
CREATE TABLE IF NOT EXISTS workflow_approvals (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  workflow_id VARCHAR(120) NOT NULL,
  approver_id BIGINT UNSIGNED NOT NULL,
  approved_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_workflow_approvals_workflow (workflow_id),
  KEY idx_workflow_approvals_approver (approver_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Per-step outcome. 'blocked' is the state FR-ORCH-003 produces and it is what
-- makes approval RESUMABLE: App\Workflow\Orchestrator::approve() reads the
-- blocked rows for the workflow and runs exactly those, using the key stored
-- here so the resume claims the same Redis key the blocked attempt would have.
--
-- step_index and idempotency_key are here rather than being recomputed because
-- a resume that re-derived them from a step list it no longer has would be
-- guessing at which effect it is allowed to perform.
CREATE TABLE IF NOT EXISTS workflow_steps (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  workflow_run_id BIGINT UNSIGNED NOT NULL,
  step_index INT UNSIGNED NOT NULL DEFAULT 0,
  step_type VARCHAR(120) NOT NULL,
  risk ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
  status ENUM('pending', 'executed', 'skipped', 'blocked', 'failed', 'compensated')
    NOT NULL DEFAULT 'pending',
  idempotency_key VARCHAR(191) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_workflow_steps_run (workflow_run_id),
  KEY idx_workflow_steps_status (status),
  KEY idx_workflow_steps_type (step_type),
  CONSTRAINT fk_workflow_steps_run FOREIGN KEY (workflow_run_id)
    REFERENCES workflow_runs (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- FR-ORCH-001, the compensation map as DATA. App\Workflow\Orchestrator mirrors
-- these pairs in code so it can compensate without a database round trip mid
-- failure - the same mirroring 003_tools uses for risk_class - but the
-- authoritative statement of "undoing a charge means issuing a refund" belongs
-- somewhere an operator can read and a migration diff can review.
CREATE TABLE IF NOT EXISTS workflow_compensations (
  step_type VARCHAR(120) NOT NULL PRIMARY KEY,
  compensating_step_type VARCHAR(120) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO workflow_compensations (step_type, compensating_step_type) VALUES
  ('charge', 'refund'),
  ('reserve_stock', 'release_stock');
