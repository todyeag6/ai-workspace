-- © AI WebScapes 2026
-- Migration 024_agent_console_permissions: the capability codes the agent
-- console is gated on.
--
-- WHY THIS IS A SEPARATE MIGRATION AND NOT PART OF 002_authz_audit: 002 seeded
-- the Phase 1 catalogue (lead.read, contact.manage, tenant.*, user.*,
-- role.assign) and the roles that carry it. The agent console is a later
-- surface with its own capabilities, and adding codes to a shipped migration
-- would rewrite history that the audit trail and TRACEABILITY.md already
-- reference. A new file keeps the catalogue's evolution legible.
--
-- WHY THE CODES ARE SPLIT IN TWO RATHER THAN ONE 'agent.manage':
-- App\Console\AgentConsoleController answers a READ question ("which agents may
-- I see") and App\Console\AgentInvocationController answers a WRITE-shaped one
-- ("run this agent, which will call a model and may call tools"). Collapsing
-- them would mean the read-only console and the invoking surface could not be
-- granted independently, and 'staff' - which needs to look at the registry but
-- has no business spending tokens or triggering tool egress - would have to be
-- given both or neither. Deny-by-default (SEC-005) only stays meaningful when
-- the capabilities are fine-grained enough to actually withhold something.
--
-- IDEMPOTENCY CONTRACT - identical to 000, 001, 002, 002_authz_audit.
-- tests/TestCase.php re-applies every migrations/*.sql file, so every statement
-- here is re-entrant: INSERT IGNORE only, no ALTER, no DROP, no CREATE.
--
-- PARSER NOTE: App\Infra\SqlSplitter strips comments and tracks string
-- literals, so a semicolon inside a comment or literal no longer splits a
-- statement. The statements below are nonetheless kept semicolon-free in prose
-- so the file stays readable under any splitter.
--
-- GRANT LOOKUPS ARE SELECT-BASED, NEVER HARDCODED IDS. permissions.id and
-- roles.id are auto-increment values that depend on the order 000/001/002 ran;
-- naming them literally would silently grant the wrong capability the moment a
-- catalogue row is inserted earlier. INSERT IGNORE ... SELECT resolves the ids
-- by their stable codes instead, and the UNIQUE keys on permissions.code and
-- uq_role_permissions_tenant_role_permission make a re-apply a no-op.

-- The two capability codes. The read code is granted widely, the invoke code
-- narrowly - see the role grants below.
INSERT IGNORE INTO permissions (code, name, description) VALUES
  ('agent.console.view', 'View the agent console', 'See the registered agents for the tenant and their active version metadata');

INSERT IGNORE INTO permissions (code, name, description) VALUES
  ('agent.invoke', 'Invoke a registered agent', 'Run a registered agent, which calls a model and may call its allow-listed tools');

-- admin: both. The role that carries every catalogue entry by construction
-- (002 grants admin the whole permissions table), so this is restated rather
-- than assumed - 002's grant ran BEFORE these codes existed, so it could not
-- have covered them.
INSERT IGNORE INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id FROM roles r, permissions p
WHERE r.tenant_id = 1 AND r.code = 'admin'
  AND p.code IN ('agent.console.view', 'agent.invoke');

-- manager: both. A manager already holds user.manage and contact.manage, and
-- operating the tenant's agents is the same class of responsibility.
INSERT IGNORE INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id FROM roles r, permissions p
WHERE r.tenant_id = 1 AND r.code = 'manager'
  AND p.code IN ('agent.console.view', 'agent.invoke');

-- staff: VIEW ONLY. staff holds lead.read, contact.manage and user.view. It may
-- see the registry - that is read-only - but must not hold agent.invoke, which
-- spends tokens, may call allow-listed tools and writes manager_tasks rows.
INSERT IGNORE INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id FROM roles r, permissions p
WHERE r.tenant_id = 1 AND r.code = 'staff'
  AND p.code IN ('agent.console.view');

-- viewer: deliberately nothing. viewer holds tenant.view and user.view and is
-- the read-only-of-read-only role. No grant statement is emitted for it, which
-- is the point: the absence is the decision, and test_viewer_holds_neither_
-- agent_console_capability asserts it so a future bulk grant cannot widen it
-- unnoticed.
