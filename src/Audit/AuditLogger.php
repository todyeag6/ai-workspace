<?php

declare(strict_types=1);

namespace App\Audit;

use App\Tenancy\TenantScope;
use InvalidArgumentException;
use JsonException;
use PDO;

/**
 * Writes immutable audit events (FR-AUD-001 / FR-AUD-002).
 *
 * WHAT THIS CLASS IS, AND IS NOT. It is a WRITER. There is deliberately no
 * update(), no delete(), and no "find and edit" - an audit trail the
 * application can rewrite is not evidence. The database backs that up with
 * BEFORE UPDATE / BEFORE DELETE triggers (migrations/007_audit.sql) that
 * SIGNAL, so even a caller that reached around this class with raw SQL would
 * be refused. Two layers, because the plan is explicit that "application-level
 * discipline alone does not satisfy 'append-only'."
 *
 * TENANT SCOPING. The write goes through prepare()+execute() with the tenant
 * bound as a parameter - never interpolated - and TenantScope validates the
 * tenant up front (null / 0 / negative throws). This is the sanctioned path:
 * the PHPStan NoUnscopedClientQueryRule forbids raw query()/exec() in src/ but
 * explicitly leaves prepare() open, which is how the scoped repositories bind
 * :tenant too.
 *
 * SECRET REDACTION (FR-AUD-002). Any value that looks like a credential -
 * a token, api key, password, secret - is replaced with '[REDACTED]' before
 * the row is written. The scrub runs over both the free-text $detail and the
 * structured $versions payload, so a webhook body captured for lineage never
 * leaks a usable secret into the audit table.
 *
 * © AI WebScapes 2026
 */
final class AuditLogger
{
    private const DETAIL_MAX = 255;

    public function __construct(private PDO $pdo)
    {
    }

    /**
     * @param  array<int|string, mixed> $versions  Version lineage, e.g. ['lead:v2'] or ['lead' => 'v2'].
     * @param  array<int|string, mixed> $payload   Structured context; redacted before store.
     */
    public function record(
        int $tenantId,
        ?int $actorUserId,
        string $action,
        ?string $objectType,
        ?string $objectId,
        string $outcome,
        string $source,
        ?string $correlationId = null,
        array $versions = [],
        array $payload = [],
        string $detail = ''
    ): int {
        // Throws for null/0/negative; the tenant is bound below, never
        // interpolated, so the scope cannot be spoofed by a caller.
        $scope = new TenantScope($tenantId);

        $safeDetail = $this->redact($detail);
        $safeVersions = $this->redactValue($versions);

        try {
            $encoded = json_encode($safeVersions, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidArgumentException('Audit versions payload could not be encoded.', 0, $e);
        }

        $sql = 'INSERT INTO audit_events ('
            . TenantScope::COLUMN . ', actor_user_id, action, object_type, object_id, '
            . 'outcome, source, correlation_id, versions, detail'
            . ') VALUES (:' . TenantScope::PARAM . ', :actor, :action, :object_type, '
            . ':object_id, :outcome, :source, :correlation_id, :versions, :detail)';

        $statement = $this->pdo->prepare($sql);
        $scope->bindTo($statement);
        $statement->bindValue('actor', $actorUserId, $actorUserId === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $statement->bindValue('action', $action);
        $statement->bindValue('object_type', $objectType, $objectType === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $statement->bindValue('object_id', $objectId, $objectId === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $statement->bindValue('outcome', $outcome);
        $statement->bindValue('source', $source);
        $statement->bindValue('correlation_id', $correlationId, $correlationId === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $statement->bindValue('versions', $encoded);
        $statement->bindValue('detail', $safeDetail === '' ? null : mb_substr($safeDetail, 0, self::DETAIL_MAX), $safeDetail === '' ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $statement->execute();

        $id = $this->pdo->lastInsertId();
        if ($id === false) {
            throw new InvalidArgumentException('Audit write reported no generated id.');
        }

        return (int) $id;
    }

    /**
     * Redacts credential-shaped values inside an arbitrary structure, recursing
     * into arrays. Keys themselves are also checked: an entry under 'token' or
     * 'apikey' is scrubbed regardless of its value's appearance.
     *
     * @param  mixed $value
     * @return mixed
     */
    private function redactValue($value)
    {
        if (is_array($value)) {
            $clean = [];
            foreach ($value as $key => $item) {
                $clean[$key] = $this->keyLooksSecret((string) $key) ? '[REDACTED]' : $this->redactValue($item);
            }

            return $clean;
        }

        if (is_string($value)) {
            return $this->redact($value);
        }

        return $value;
    }

    /**
     * Replaces credential-shaped substrings in a free-text string. The pattern
     * catches assignments ("token=...", "api_key: ..."), quoted secrets, and
     * long high-entropy blobs (>= 16 hex/base64-ish chars) that are the
     * hallmark of a leaked key.
     */
    private function redact(string $text): string
    {
        if ($text === '') {
            return '';
        }

        $patterns = [
            '/(token|secret|password|passwd|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token)\s*[:=]\s*\S+/i',
            '/[A-Za-z0-9_\-]{16,}/',          // high-entropy blobs
            '/"(token|secret|password|apikey)"\s*:\s*"[^"]*"/i',
        ];

        return preg_replace($patterns, '[REDACTED]', $text) ?? $text;
    }

    private function keyLooksSecret(string $key): bool
    {
        return (bool) preg_match('/^(token|secret|password|passwd|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token)$/i', $key);
    }
}
