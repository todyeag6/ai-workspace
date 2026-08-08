-- © AI WebScapes 2026
-- Migration 009_dashboard: telemetry columns the operations dashboard reads.
--
-- P1-T15 (FR-DASH-001/002, LFR-DASH-001/002/003, A11Y-001..006) needs a
-- "failed deliveries" queue on the dashboard. The message_deliveries table
-- created in 006 carries no dispatch outcome, so failedDeliveries() had no
-- real signal to read. We add a nullable status + error column so the queue
-- is backed by data, not invented.
--
-- IDEMPOTENCY CONTRACT: migrations are re-applied (once per process) by
-- tests/TestCase.php and scripts/migrate.php through App\Infra\SqlSplitter.
-- MySQL has no `ADD COLUMN IF NOT EXISTS`, so each add is guarded with an
-- information_schema probe and a no-op SET when the column exists.
--
-- PARSER NOTE: SqlSplitter splits on ';'. There are no trigger bodies here, so
-- no DELIMITER block is required.
--
-- IMPORTANT: the no-op branch uses `SET @skip = 0` (which returns NO result
-- set) rather than `SELECT 1` (which would leave an unbuffered result that
-- blocks the next statement with SQLSTATE 2014). This is load-bearing.

-- message_deliveries.status: NULL = outcome not yet recorded; the dashboard
-- counts status = 'failed'. Kept VARCHAR (not ENUM) so a future dispatch layer
-- can record intermediate states without another migration.
SET @db = DATABASE();
SELECT COUNT(*) INTO @has_status FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'message_deliveries' AND COLUMN_NAME = 'status';
SET @sql_status = IF(@has_status = 0,
  'ALTER TABLE message_deliveries ADD COLUMN status VARCHAR(16) NULL AFTER channel',
  'SET @skip = 0');
PREPARE stmt_status FROM @sql_status;
EXECUTE stmt_status;
DEALLOCATE PREPARE stmt_status;

-- message_deliveries.error: the reason a delivery failed (fail-closed audit of
-- why an outbound message did not leave the system). Free text, capped by the
-- application; nullable.
SELECT COUNT(*) INTO @has_error FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'message_deliveries' AND COLUMN_NAME = 'error';
SET @sql_error = IF(@has_error = 0,
  'ALTER TABLE message_deliveries ADD COLUMN error VARCHAR(255) NULL AFTER status',
  'SET @skip = 0');
PREPARE stmt_error FROM @sql_error;
EXECUTE stmt_error;
DEALLOCATE PREPARE stmt_error;
