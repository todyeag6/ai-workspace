<?php

declare(strict_types=1);

namespace App\Connectors;

/**
 * The actor half of the P2-T2 connector SDK.
 *
 * WHY AN INTERFACE AND A REGISTRY, NOT DIRECT CALLS IN THE GATE: the P1-T8
 * ToolGateway already established that the component which DECIDES (allowlist,
 * SSRF, egress, high-impact authority) must not be the one that ACTS. The
 * connector SDK is the actor. It receives a ConnectorSpec that came from the
 * vetted catalogue and a set of parameters the gateway already validated, and
 * it performs exactly one side effect - the egress to the connector's
 * base_url. It performs NO routing, NO allowlist and NO SSRF check of its own:
 * those were settled upstream, and re-checking them here would be a second,
 * driftable copy of the policy.
 *
 * supports() lets the executor pick the right client by connector TYPE without
 * a denylist or a switch that forgets a type. execute() returns the raw
 * downstream response so callers can disposition it; the SDK never decides
 * whether an outcome was "good".
 *
 * © AI WebScapes 2026
 */
interface ConnectorClient
{
    /**
     * Whether this client handles the given connector type (crm | http | email).
     */
    public function supports(string $type): bool;

    /**
     * Performs the call against the connector. The transport is injected by the
     * concrete client, so no implementation here reaches the network directly
     * - that is what makes every client unit-testable without a socket.
     *
     * @param array<string, mixed> $params Validated parameters (already
     *                                     SSRF/egress-checked by ToolGateway).
     * @return array{status: string, payload: mixed, connector: string}
     */
    public function execute(ConnectorSpec $spec, array $params): array;
}
