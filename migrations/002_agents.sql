-- © AI WebScapes 2026
-- Migration 002_agents: the enterprise agent registry (P1-T5).
--
-- Covers FR-AGENT-001 (a register of every agent with its owner, purpose,
-- version, risk class, allowed tools, data classes, model config, deployment
-- location, status and retirement date), FR-AGENT-002 (disabled by default,
-- activation only through a release gate) and FR-AGENT-003 (a prompt or
-- config change is a NEW immutable version row, never an edit in place).
--
-- IDEMPOTENCY CONTRACT - identical to 000, 001 and 002_authz_audit.
-- tests/TestCase.php re-applies every migrations/*.sql file, so every
-- statement here is re-entrant: CREATE TABLE IF NOT EXISTS, inline indexes,
-- INSERT IGNORE only. No ALTER, no DROP.
--
-- PARSER NOTE: both tests/TestCase.php and scripts/migrate.php split this file
-- on the semicolon character. No semicolon may appear inside a comment or a
-- string literal. No DELIMITER blocks, no stored procedures, no triggers.
--
-- ORDERING NOTE: this file sorts BEFORE 002_authz_audit.sql lexicographically
-- (ag < au) and both sort after 001. That is safe because agents depends only
-- on tenants, which 001 creates and seeds.

-- WHY status DEFAULTS TO 'disabled' IN THE SCHEMA AND NOT ONLY IN PHP:
-- FR-AGENT-002 is a safety property, and a safety property that lives in one
-- application method is one forgotten INSERT away from being false. The column
-- default means a row created by a migration, a fixture, an import or a future
-- repository is still born switched off. App\Agents\AgentRegistry sets it
-- explicitly as well - belt and braces, because the two can be checked
-- independently.
--
-- WHY active_version_id CARRIES NO FOREIGN KEY: agents and agent_versions
-- reference each other, and a circular FK cannot be expressed in two
-- CREATE TABLE statements without a follow-up ALTER, which the idempotency
-- contract above forbids. agent_versions.agent_id carries the real referential
-- integrity (that is the direction that matters - a version cannot exist
-- without its agent), and this column is an indexed pointer maintained by
-- App\Agents\AgentRepository.
CREATE TABLE IF NOT EXISTS agents (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  name VARCHAR(160) NOT NULL,
  owner VARCHAR(160) NOT NULL,
  purpose VARCHAR(500) NOT NULL,
  risk_class ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'high',
  data_classes VARCHAR(512) NOT NULL DEFAULT '[]',
  deployment_location ENUM('cloud', 'hybrid', 'client_cloud', 'local') NOT NULL DEFAULT 'cloud',
  status ENUM('disabled', 'active', 'retired') NOT NULL DEFAULT 'disabled',
  active_version_id BIGINT UNSIGNED NULL DEFAULT NULL,
  retirement_date DATE NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_agents_tenant_name (tenant_id, name),
  KEY idx_agents_tenant (tenant_id),
  KEY idx_agents_status (status),
  KEY idx_agents_active_version (active_version_id),
  KEY idx_agents_retirement_date (retirement_date),
  CONSTRAINT fk_agents_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- FR-AGENT-003. An append-only table: rows are INSERTed and never UPDATEd.
-- The prompt, the model config and the allowed-tools list all live HERE rather
-- than on agents, so "what was this agent allowed to do on the day it did
-- that" has an answer that no later change can rewrite - which is what makes
-- the audit trail in 002_authz_audit worth keeping.
--
-- tenant_id is carried denormalised even though it is derivable through
-- agent_id. AC-001 is enforced by App\Data\TenantRepository, which puts
-- `tenant_id = :tenant` into every statement it emits against a single table.
-- A version table without its own tenant column could only be scoped through
-- a join the base class does not write, so the guarantee would degrade from
-- structural to conventional exactly where the sensitive payload lives.
CREATE TABLE IF NOT EXISTS agent_versions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  agent_id BIGINT UNSIGNED NOT NULL,
  version_number INT UNSIGNED NOT NULL,
  system_prompt TEXT NOT NULL,
  model_config VARCHAR(2048) NOT NULL DEFAULT '[]',
  allowed_tools VARCHAR(2048) NOT NULL DEFAULT '[]',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_agent_versions_agent_number (tenant_id, agent_id, version_number),
  KEY idx_agent_versions_tenant (tenant_id),
  KEY idx_agent_versions_agent (agent_id),
  CONSTRAINT fk_agent_versions_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  CONSTRAINT fk_agent_versions_agent FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The release-gate names an activation is checked against. Seeded as reference
-- data rather than hard-coded in PHP so an operator can see what the gate
-- means without reading the source. P1-T5 records the gates. Evaluating them
-- automatically is P1-T8 territory - AgentRegistry::activate() takes the
-- verdict as an explicit argument and refuses to guess.
CREATE TABLE IF NOT EXISTS agent_release_gates (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(64) NOT NULL UNIQUE,
  description VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO agent_release_gates (code, description)
VALUES ('security_review', 'Security review of prompt, tools and data classes signed off');

INSERT IGNORE INTO agent_release_gates (code, description)
VALUES ('eval_suite', 'Behavioural evaluation suite passed for the version being activated');

INSERT IGNORE INTO agent_release_gates (code, description)
VALUES ('owner_signoff', 'Named business owner accepted accountability for the agent');
