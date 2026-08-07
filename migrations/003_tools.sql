-- © AI WebScapes 2026
-- Migration 003_tools: the tool and connector registry (P1-T8).
--
-- Covers FR-TOOL-001 (every tool an agent may call is registered and granted
-- explicitly), FR-TOOL-002/003 (the risk class and connector a call is bound
-- to are data, not code comments) and AC-002 (grants are an allowlist keyed by
-- agent AND agent version - a new version starts with no tools).
--
-- IDEMPOTENCY CONTRACT - identical to 000, 001, 002_agents and 002_authz_audit.
-- tests/TestCase.php re-applies every migrations/*.sql file, so every
-- statement here is re-entrant: CREATE TABLE IF NOT EXISTS, inline indexes,
-- INSERT IGNORE only. No ALTER, no DROP.
--
-- PARSER NOTE: both tests/TestCase.php and scripts/migrate.php split this file
-- on the semicolon character. No semicolon may appear inside a comment or a
-- string literal. No DELIMITER blocks, no stored procedures, no triggers.

-- WHY risk_class LIVES HERE AND NOT ONLY IN PHP: App\Tools\ToolGateway mirrors
-- these values so it can refuse before it has a database connection, but the
-- authoritative statement of "refund is high impact" has to be inspectable by
-- an operator and reviewable in a migration diff. FR-AI-006 turns on this
-- column: high and critical route through App\AI\ActionAuthority, which
-- refuses to let a model authorise them.
--
-- No tenant_id: this is a catalogue of tool TYPES, the same for every tenant,
-- and it holds no client data. The per-tenant question is which agent may call
-- which tool, and that is agent_tools below.
CREATE TABLE IF NOT EXISTS tools (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  risk_class ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'high',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_tools_name (name),
  KEY idx_tools_risk_class (risk_class)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The outside systems a tool may reach. base_url is the approved egress
-- target: the gateway's egress allowlist (FR-TOOL-003) is configured from
-- entries like these, which is why the column is here rather than being
-- assembled at call time from whatever the model supplied.
--
-- NO CREDENTIAL COLUMN, ON PURPOSE. Scoped least-privilege secrets per tenant
-- and environment belong to App\Config\SecretsProvider (P1-T2). Duplicating a
-- token into a catalogue row would put it in every backup and every SELECT *.
CREATE TABLE IF NOT EXISTS connectors (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  type VARCHAR(60) NOT NULL,
  base_url VARCHAR(512) NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_connectors_name (name),
  KEY idx_connectors_type (type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- AC-002, the allowlist itself. The primary key is (agent, agent_version,
-- tool): a grant is a statement about one reviewed version of one agent, so
-- publishing v2 of an agent grants it NOTHING until rows are added for v2.
-- That is the point - carrying grants forward silently would make the release
-- gate in FR-AGENT-002 decorative.
--
-- agent and agent_version are strings rather than a foreign key to
-- agent_versions.id because the gateway is constructed from a call context
-- ("agent lead, version v3") and must be able to refuse a name that has no
-- row at all. A FK would make the unknown-agent case a database error instead
-- of a clean AC-002 refusal.
--
-- NO deny column. There is deliberately no way to express "deny X" here: a
-- denylist next to an allowlist is an invitation to grant broadly and patch
-- afterwards, and the two disagree the moment a tool is added.
CREATE TABLE IF NOT EXISTS agent_tools (
  agent VARCHAR(120) NOT NULL,
  agent_version VARCHAR(60) NOT NULL,
  tool VARCHAR(120) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (agent, agent_version, tool),
  KEY idx_agent_tools_tool (tool)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Reference data: the tool catalogue the gateway mirrors. INSERT IGNORE keeps
-- re-application a no-op, and the UNIQUE key on name is what makes it one.
INSERT IGNORE INTO tools (name, risk_class) VALUES ('send_email', 'medium');

INSERT IGNORE INTO tools (name, risk_class) VALUES ('http_fetch', 'low');

INSERT IGNORE INTO tools (name, risk_class) VALUES ('webhook', 'medium');

INSERT IGNORE INTO tools (name, risk_class) VALUES ('crm_lookup', 'low');

INSERT IGNORE INTO tools (name, risk_class) VALUES ('calendar_read', 'low');

INSERT IGNORE INTO tools (name, risk_class) VALUES ('refund', 'high');

INSERT IGNORE INTO tools (name, risk_class) VALUES ('delete_db', 'critical');

INSERT IGNORE INTO tools (name, risk_class) VALUES ('wire_transfer', 'critical');

INSERT IGNORE INTO tools (name, risk_class) VALUES ('contract_sign', 'critical');

-- The starting grant for the lead-handling agent: read and notify, nothing
-- that moves money or deletes anything. Any high-impact tool would still hit
-- ActionAuthority even if it were granted here.
INSERT IGNORE INTO agent_tools (agent, agent_version, tool) VALUES ('lead', 'v1', 'send_email');

INSERT IGNORE INTO agent_tools (agent, agent_version, tool) VALUES ('lead', 'v1', 'crm_lookup');
