-- © AI WebScapes 2026
-- Migration 010_agent_eval: the evaluation harness's append-only ledger (P2-T1).
--
-- FR-AGENT-003 gates agent activation on a passing evaluation. The evaluation
-- RESULT must be durable and tamper-evident: a release gate whose verdict can
-- be quietly edited after the fact is not a gate. So the outcome lives in its
-- OWN append-only table, never on agent_versions (which is immutable by design
-- - see migrations/002_agents.sql and App\Agents\AgentVersionRepository).
--
-- IDEMPOTENCY CONTRACT (identical to 000/001/002): no ALTER, no DROP, no
-- trigger, no DELIMITER block. CREATE TABLE IF NOT EXISTS. The harness appends
-- one row per run; tests/TestCase.php re-applies this file per test, so it must
-- be re-entrant. No semicolon inside a comment or string literal.
--
-- tenant_id is carried denormalised for the same AC-001 reason as
-- agent_versions: App\Data\TenantRepository scopes every statement by it, and a
-- table without its own tenant column could only be scoped through a join the
-- base class does not write.
CREATE TABLE IF NOT EXISTS agent_evaluations (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  agent_id BIGINT UNSIGNED NOT NULL,
  version_id BIGINT UNSIGNED NOT NULL,
  run_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  passed TINYINT(1) NOT NULL,
  cases_run INT UNSIGNED NOT NULL DEFAULT 0,
  failed_kpis VARCHAR(512) NOT NULL DEFAULT '',
  -- Snapshot of the thresholds in force at run time, so a later threshold
  -- change cannot rewrite the meaning of a recorded pass.
  thresholds_json VARCHAR(2048) NOT NULL DEFAULT '[]',
  KEY idx_agent_evaluations_tenant (tenant_id),
  KEY idx_agent_evaluations_agent (agent_id),
  KEY idx_agent_evaluations_version (version_id),
  CONSTRAINT fk_agent_evaluations_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
