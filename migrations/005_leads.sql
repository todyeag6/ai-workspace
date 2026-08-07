-- © AI WebScapes 2026
-- Migration 005_leads: the lead lifecycle schema (Lead FRD Table 3).
-- Covers LFR-CAP-001..004 (public capture) and LBR-5.1 (a lead survives an AI
-- failure), plus the tables the later lead tasks hang off: submissions, AI
-- analyses, field corrections, interactions, tasks, status history, duplicate
-- links, message templates and notifications.
--
-- AC-001 - EVERY table here carries tenant_id NOT NULL with a foreign key to
-- tenants(id) and a leading tenant index, because all of it is CLIENT data. No
-- row in this migration is reachable without naming a tenant, which is what
-- lets App\Tenancy\TenantScope generate the predicate for all of them.
--
-- IDEMPOTENCY CONTRACT - tests/TestCase.php re-applies every migrations/*.sql
-- before a test whenever the schema looks absent, so every statement below is
-- re-entrant: CREATE TABLE IF NOT EXISTS only, indexes declared INLINE (MySQL
-- has no CREATE INDEX IF NOT EXISTS), seeds via INSERT IGNORE, and no DROP or
-- bare ALTER anywhere.
--
-- PARSER NOTE: tests/TestCase.php and scripts/migrate.php split this file on
-- the semicolon character. No semicolon may appear inside a comment or a
-- string literal in this file.

-- The lead itself. status is an ENUM rather than free text so that 'Review' -
-- the state LBR-5.1 requires after a failed analysis - cannot be misspelled
-- into a state nothing queries for.
CREATE TABLE IF NOT EXISTS leads (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  correlation_id CHAR(32) NOT NULL,
  email VARCHAR(190) NOT NULL,
  name VARCHAR(120) NOT NULL,
  company VARCHAR(160) NULL,
  source VARCHAR(64) NOT NULL DEFAULT 'public_form',
  status ENUM('New', 'Review', 'Qualified', 'Disqualified', 'Converted')
    NOT NULL DEFAULT 'New',
  ip_hash CHAR(64) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_leads_tenant_correlation (tenant_id, correlation_id),
  KEY idx_leads_tenant (tenant_id),
  KEY idx_leads_tenant_status (tenant_id, status),
  KEY idx_leads_tenant_email (tenant_id, email),
  CONSTRAINT fk_leads_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The raw submission, kept verbatim next to the parsed lead. LFR-CAP-004 asks
-- for persist-before-AI: this row is what proves what the visitor actually
-- sent, independently of whatever the model later decides the fields mean.
CREATE TABLE IF NOT EXISTS lead_submissions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  lead_id BIGINT UNSIGNED NOT NULL,
  payload_json JSON NOT NULL,
  ip_hash CHAR(64) NULL,
  user_agent VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_lead_submissions_tenant (tenant_id),
  KEY idx_lead_submissions_lead (tenant_id, lead_id),
  CONSTRAINT fk_lead_submissions_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_lead_submissions_lead FOREIGN KEY (lead_id) REFERENCES leads (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The queued AI analysis. Written AFTER the lead is committed, and it carries
-- its own status so a failure is recorded as data rather than lost with the
-- lead (LBR-5.1).
CREATE TABLE IF NOT EXISTS lead_ai_analyses (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  lead_id BIGINT UNSIGNED NOT NULL,
  status ENUM('pending', 'complete', 'failed') NOT NULL DEFAULT 'pending',
  analysis_json JSON NULL,
  error_message VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_lead_ai_analyses_tenant (tenant_id),
  KEY idx_lead_ai_analyses_lead (tenant_id, lead_id),
  KEY idx_lead_ai_analyses_status (tenant_id, status),
  CONSTRAINT fk_lead_ai_analyses_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_lead_ai_analyses_lead FOREIGN KEY (lead_id) REFERENCES leads (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Human corrections of AI-extracted fields, kept as an append-only trail so the
-- model's error rate stays measurable instead of being overwritten in place.
CREATE TABLE IF NOT EXISTS lead_field_corrections (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  lead_id BIGINT UNSIGNED NOT NULL,
  field_name VARCHAR(64) NOT NULL,
  old_value TEXT NULL,
  new_value TEXT NULL,
  corrected_by BIGINT UNSIGNED NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_lead_field_corrections_tenant (tenant_id),
  KEY idx_lead_field_corrections_lead (tenant_id, lead_id),
  CONSTRAINT fk_lead_field_corrections_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_lead_field_corrections_lead FOREIGN KEY (lead_id) REFERENCES leads (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS lead_interactions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  lead_id BIGINT UNSIGNED NOT NULL,
  channel ENUM('email', 'phone', 'meeting', 'note') NOT NULL DEFAULT 'note',
  direction ENUM('inbound', 'outbound', 'internal') NOT NULL DEFAULT 'internal',
  body TEXT NULL,
  actor_id BIGINT UNSIGNED NULL,
  occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_lead_interactions_tenant (tenant_id),
  KEY idx_lead_interactions_lead (tenant_id, lead_id),
  CONSTRAINT fk_lead_interactions_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_lead_interactions_lead FOREIGN KEY (lead_id) REFERENCES leads (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS lead_tasks (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  lead_id BIGINT UNSIGNED NOT NULL,
  title VARCHAR(190) NOT NULL,
  status ENUM('open', 'done', 'cancelled') NOT NULL DEFAULT 'open',
  due_at DATETIME NULL,
  assigned_to BIGINT UNSIGNED NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_lead_tasks_tenant (tenant_id),
  KEY idx_lead_tasks_lead (tenant_id, lead_id),
  KEY idx_lead_tasks_status (tenant_id, status),
  CONSTRAINT fk_lead_tasks_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_lead_tasks_lead FOREIGN KEY (lead_id) REFERENCES leads (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Append-only status trail. from_status is nullable because the first row is
-- the creation of the lead, which has no previous state.
CREATE TABLE IF NOT EXISTS lead_status_history (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  lead_id BIGINT UNSIGNED NOT NULL,
  from_status VARCHAR(32) NULL,
  to_status VARCHAR(32) NOT NULL,
  reason VARCHAR(190) NULL,
  changed_by BIGINT UNSIGNED NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_lead_status_history_tenant (tenant_id),
  KEY idx_lead_status_history_lead (tenant_id, lead_id),
  CONSTRAINT fk_lead_status_history_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_lead_status_history_lead FOREIGN KEY (lead_id) REFERENCES leads (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Suspected duplicate pairs. The unique key is per tenant, so the same pair of
-- ids in two tenants is two independent facts.
CREATE TABLE IF NOT EXISTS lead_duplicates (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  lead_id BIGINT UNSIGNED NOT NULL,
  duplicate_lead_id BIGINT UNSIGNED NOT NULL,
  score DECIMAL(5, 4) NOT NULL DEFAULT 0,
  status ENUM('suspected', 'confirmed', 'dismissed') NOT NULL DEFAULT 'suspected',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_lead_duplicates_pair (tenant_id, lead_id, duplicate_lead_id),
  KEY idx_lead_duplicates_tenant (tenant_id),
  CONSTRAINT fk_lead_duplicates_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_lead_duplicates_lead FOREIGN KEY (lead_id) REFERENCES leads (id) ON DELETE CASCADE,
  CONSTRAINT fk_lead_duplicates_other FOREIGN KEY (duplicate_lead_id) REFERENCES leads (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Outbound copy, per tenant: two tenants may hold the same template code with
-- entirely different wording, so code is unique WITHIN a tenant only.
CREATE TABLE IF NOT EXISTS message_templates (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  code VARCHAR(64) NOT NULL,
  name VARCHAR(120) NOT NULL,
  channel ENUM('email', 'sms', 'internal') NOT NULL DEFAULT 'email',
  subject VARCHAR(190) NULL,
  body TEXT NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_message_templates_tenant_code (tenant_id, code),
  KEY idx_message_templates_tenant (tenant_id),
  CONSTRAINT fk_message_templates_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notifications (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tenant_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NULL,
  lead_id BIGINT UNSIGNED NULL,
  type VARCHAR(64) NOT NULL,
  payload_json JSON NULL,
  read_at TIMESTAMP NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_notifications_tenant (tenant_id),
  KEY idx_notifications_unread (tenant_id, read_at),
  KEY idx_notifications_lead (tenant_id, lead_id),
  CONSTRAINT fk_notifications_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id),
  CONSTRAINT fk_notifications_lead FOREIGN KEY (lead_id) REFERENCES leads (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed for the default tenant. The acknowledgement wording is deliberately
-- GENERIC - LFR-CAP-001 requires that a honeypot hit and a real capture are
-- indistinguishable to the sender, so the same receipt text serves both.
INSERT IGNORE INTO message_templates (tenant_id, code, name, channel, subject, body) VALUES
  (1, 'lead_ack', 'Lead acknowledgement', 'email', 'We received your request',
   'Thanks for reaching out. Our team will review your request and follow up shortly.'),
  (1, 'lead_review', 'Lead needs review', 'internal', 'Lead parked for review',
   'Automated analysis did not complete for this lead. Please review it manually.');
