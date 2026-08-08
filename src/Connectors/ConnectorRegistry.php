<?php

declare(strict_types=1);

namespace App\Connectors;

use PDO;
use RuntimeException;

/**
 * Resolves a tool to the connector that serves it (P2-T2).
 *
 * Reads the vetted `connector_bindings` + `connectors` catalogue. This is a
 * read-only catalogue lookup - it performs no auth, no SSRF check and no
 * egress: those were settled by ToolGateway before anything reaches here. The
 * registry exists so the executable binding is data (visible in a migration
 * diff) rather than a code comment, and so the executor can stay generic.
 *
 * Tenant-global by design: like `tools` and `connectors`, these tables hold
 * type relationships and no client data, so there is no tenant_id column and
 * no scoping predicate. A missing binding is a configuration error, not a
 * per-tenant absence, hence the explicit exception rather than a silent null.
 *
 * © AI WebScapes 2026
 */
final class ConnectorRegistry
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    /**
     * @throws RuntimeException When the tool has no connector binding, or the
     *                          bound connector row is missing - running an
     *                          unbound tool would mean inventing a destination.
     */
    public function resolve(string $tool): ConnectorSpec
    {
        $stmt = $this->pdo->prepare(
            'SELECT c.name, c.type, c.base_url '
            . 'FROM connector_bindings b '
            . 'JOIN connectors c ON c.id = b.connector_id '
            . 'WHERE b.tool = :tool LIMIT 1'
        );
        $stmt->execute(['tool' => $tool]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row === false || !is_array($row)) {
            throw new RuntimeException(sprintf('No connector binding for tool "%s".', $tool));
        }

        return new ConnectorSpec(
            (string) $row['name'],
            (string) $row['type'],
            (string) $row['base_url']
        );
    }
}
