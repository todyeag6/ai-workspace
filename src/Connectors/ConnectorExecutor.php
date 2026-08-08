<?php

declare(strict_types=1);

namespace App\Connectors;

use RuntimeException;

/**
 * The actor that performs an APPROVED tool call through its connector (P2-T2).
 *
 * This class is the counterpart to App\Tools\ToolGateway, which DECIDES. The
 * gateway returns an "allowed" record; this executor takes that record and
 * performs the single side effect it authorises - the egress to the connector
 * resolved from the catalogue. It performs NO allowlist, SSRF, egress or
 * authority checks of its own: re-checking here would be a second, driftable
 * copy of the policy the gateway already enforced. If the gateway did not run,
 * this class must not be called.
 *
 * CLIENT SELECTION: the executor holds the catalogue of clients and picks the
 * one whose supports() matches the resolved connector TYPE. Adding a connector
 * type means adding a client here - there is no implicit default that would
 * silently swallow an unknown type.
 *
 * © AI WebScapes 2026
 */
final class ConnectorExecutor
{
    /**
     * @param list<ConnectorClient> $clients
     */
    public function __construct(
        private readonly ConnectorRegistry $registry,
        private readonly array $clients
    ) {
    }

    /**
     * @param array<string, mixed> $decision
     *              The record returned by ToolGateway::invoke() (status must be
     *              'allowed'). Typed loosely on purpose: the gateway's record
     *              is validated by assertion below, and a precise shape here
     *              fights phpstan's narrowing of the status check.
     * @return array{status: string, payload: mixed, connector: string}
     *
     * @throws RuntimeException When the decision was not "allowed", or no
     *                          client handles the connector type.
     */
    public function run(array $decision): array
    {
        if (($decision['status'] ?? '') !== 'allowed') {
            throw new RuntimeException(sprintf(
                'Refusing to execute tool "%s": the gateway did not allow it (status "%s").',
                $decision['tool'] ?? '',
                $decision['status'] ?? 'unknown'
            ));
        }

        $tool = $decision['tool'];
        $spec = $this->registry->resolve($tool);

        foreach ($this->clients as $client) {
            if ($client->supports($spec->type)) {
                return $client->execute($spec, $decision['params'] ?? []);
            }
        }

        throw new RuntimeException(sprintf(
            'No connector client handles type "%s" for tool "%s".',
            $spec->type,
            $tool
        ));
    }
}
