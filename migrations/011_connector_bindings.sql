-- © AI WebScapes 2026
-- Migration 011_connector_bindings: which connector serves which tool (P2-T2).
--
-- The P1-T8 catalogue (migration 003) has a `connectors` table (the vetted
-- outside systems a tool may reach) but no link from a TOOL to a connector.
-- P2-T2 adds the connector SDK that executes an approved tool call through its
-- connector, and it needs that binding as data, not a code comment - so the
-- operator can see "crm_lookup is served by the HubSpot connector" in a
-- migration diff and change it without touching PHP.
--
-- IDEMPOTENCY CONTRACT (identical to 000..010): no ALTER, no DROP, no trigger,
-- no DELIMITER block, no semicolon inside a comment or string literal. CREATE
-- TABLE IF NOT EXISTS + INSERT IGNORE only. tests/TestCase.php re-applies this
-- file per test, so it must be re-entrant. No tenant_id: like `tools` and
-- `connectors`, this is a catalogue of TYPE relationships, not client data.
--
-- A tool may bind to at most one connector (the PK is tool). A connector may
-- serve many tools. The FK to connectors(id) is the only cross-table link and
-- it points at the catalogue, never at tenant rows.
CREATE TABLE IF NOT EXISTS connector_bindings (
  tool VARCHAR(120) NOT NULL,
  connector_id BIGINT UNSIGNED NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tool),
  KEY idx_connector_bindings_connector (connector_id),
  CONSTRAINT fk_connector_bindings_connector FOREIGN KEY (connector_id) REFERENCES connectors(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The connector catalogue rows. 003 created the `connectors` table but seeded
-- none; these are the vetted outside systems the connector SDK may reach. The
-- base_url is an approved egress target (FR-TOOL-003), sourced from here
-- rather than from anything a model supplied. INSERT IGNORE keeps this
-- re-entrant. No credentials: scoped secrets live in SecretsProvider (P1-T2).
INSERT IGNORE INTO connectors (name, type, base_url) VALUES
  ('hubspot', 'crm', 'https://api.hubspot.com'),
  ('web', 'http', 'https://api.aiwebscapes.test'),
  ('smtp', 'email', 'smtp://smtp.aiwebscapes.test');

-- Seed: bind the P1-T8 seeded tools to the connectors they reach. These rows
-- are the executable half of the P1-T8 catalogue. INSERT IGNORE keeps
-- re-application a no-op.
INSERT IGNORE INTO connector_bindings (tool, connector_id)
SELECT 'crm_lookup', c.id FROM connectors c WHERE c.name = 'hubspot' LIMIT 1;
INSERT IGNORE INTO connector_bindings (tool, connector_id)
SELECT 'http_fetch', c.id FROM connectors c WHERE c.name = 'web' LIMIT 1;
INSERT IGNORE INTO connector_bindings (tool, connector_id)
SELECT 'send_email', c.id FROM connectors c WHERE c.name = 'smtp' LIMIT 1;
INSERT IGNORE INTO connector_bindings (tool, connector_id)
SELECT 'webhook', c.id FROM connectors c WHERE c.name = 'web' LIMIT 1;
