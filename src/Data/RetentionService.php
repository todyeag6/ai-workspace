<?php

declare(strict_types=1);

namespace App\Data;

use App\Tenancy\TenantScope;
use DomainException;
use PDO;
use RuntimeException;

/**
 * Verified data deletion (FR-DATA-002).
 *
 * Deletes a tenant's rows for a known data class, then PROVES the erasure by
 * re-counting: if any row remains, the operation is a hard failure, never a
 * "best effort". When verification is requested, a proof row is written to
 * data_deletion_verifications so the erasure is auditable afterwards.
 *
 * DENY-BY-DEFAULT (SEC-005). The class-to-table mapping is a fixed allowlist.
 * A caller cannot point deletion at an arbitrary table; an unknown class is
 * refused outright. The delete itself is tenant-scoped through TenantScope and
 * prepare()+execute() - the sanctioned path the PHPStan
 * NoUnscopedClientQueryRule leaves open - so a caller cannot erase another
 * tenant's data.
 *
 * © AI WebScapes 2026
 */
final class RetentionService
{
    /**
     * The only classes deletion may target. Expanding this list is a deliberate
     * code change, reviewed like any other - not something a request can widen.
     *
     * @var array<string, string>
     */
    private const ALLOWED_CLASSES = [
        'lead' => 'leads',
    ];

    public function __construct(private PDO $pdo)
    {
    }

    /**
     * @throws DomainException  When $dataClass is not in the allowlist.
     * @throws RuntimeException When $verify is true but rows remain after delete.
     */
    public function deleteTenantData(int $tenantId, string $dataClass, bool $verify = true): DeletionResult
    {
        if (!array_key_exists($dataClass, self::ALLOWED_CLASSES)) {
            throw new DomainException(sprintf('Refusing to delete unknown data class "%s".', $dataClass));
        }

        $table = self::ALLOWED_CLASSES[$dataClass];
        $scope = new TenantScope($tenantId);

        $delete = $this->pdo->prepare('DELETE FROM ' . $table . ' WHERE ' . TenantScope::COLUMN . ' = :' . TenantScope::PARAM);
        $scope->bindTo($delete);
        $delete->execute();
        $deleted = $delete->rowCount();

        $verified = false;
        $verificationId = 0;

        if ($verify) {
            $remaining = $this->countRemaining($table, $scope);
            if ($remaining > 0) {
                throw new RuntimeException(sprintf(
                    'Deletion of "%s" for tenant %d was NOT verified: %d row(s) still present.',
                    $dataClass,
                    $tenantId,
                    $remaining
                ));
            }

            $verified = true;
            $verificationId = $this->recordVerification($tenantId, $dataClass);
        }

        return new DeletionResult($deleted, $verified, $verificationId);
    }

    public function deletionVerified(int $tenantId, string $dataClass): bool
    {
        $statement = $this->pdo->prepare(
            'SELECT COUNT(*) FROM data_deletion_verifications '
            . 'WHERE tenant_id = :tenant AND data_class = :class'
        );
        $statement->execute(['tenant' => $tenantId, 'class' => $dataClass]);
        $count = $statement->fetchColumn();

        return is_string($count) || is_int($count) ? (int) $count > 0 : false;
    }

    /**
     * @throws RuntimeException
     */
    private function countRemaining(string $table, TenantScope $scope): int
    {
        $statement = $this->pdo->prepare('SELECT COUNT(*) FROM ' . $table . ' WHERE ' . TenantScope::COLUMN . ' = :' . TenantScope::PARAM);
        $scope->bindTo($statement);
        $statement->execute();
        $count = $statement->fetchColumn();

        return is_string($count) || is_int($count) ? (int) $count : 0;
    }

    private function recordVerification(int $tenantId, string $dataClass): int
    {
        $statement = $this->pdo->prepare(
            'INSERT INTO data_deletion_verifications (tenant_id, data_class) VALUES (:tenant, :class)'
        );
        $statement->execute(['tenant' => $tenantId, 'class' => $dataClass]);
        $id = $this->pdo->lastInsertId();

        return is_string($id) ? (int) $id : 0;
    }
}
