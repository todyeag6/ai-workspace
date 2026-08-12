<?php

declare(strict_types=1);

namespace App\Deploy;

/**
 * Opt-in remote-support telemetry (P4-T10).
 *
 * SEC-005 deny-by-default: telemetry transmits ONLY when the policy is enabled
 * AND the target endpoint is on the policy's allowlist (FR-TOOL-003 — egress is
 * never a model-output-controlled URL). The payload is a CLOSED set of
 * operational keys (health / version / exception count) — no client data, no
 * leads (AC-001/002). Pure decision logic; the actual HTTP send is the caller's
 * job and must target endpoint() only.
 */
final class RemoteSupport
{
    /**
     * @param array<string,mixed> $policy
     * @param list<string>         $configuredEndpoints Endpoints the deployment
     *                                        operator has actually wired (intersection
     *                                        with the policy allowlist decides transmission).
     */
    public function __construct(
        private readonly array $policy,
        private readonly array $configuredEndpoints = []
    ) {
    }

    public function mayTransmit(): bool
    {
        if (!($this->policy['enabled'] ?? false)) {
            return false;
        }
        return $this->endpoint() !== null;
    }

    /**
     * The single allowlisted endpoint to transmit to, or null when transmission
     * is not permitted. Intersection of policy allowlist and configured endpoints.
     */
    public function endpoint(): ?string
    {
        $allow = $this->policy['allowed_endpoints'] ?? [];
        if (!is_array($allow) || $allow === []) {
            return null;
        }
        foreach ($allow as $candidate) {
            if (in_array($candidate, $this->configuredEndpoints, true)) {
                return (string) $candidate;
            }
        }
        return null;
    }

    /**
     * @param array<string,mixed> $healthStatus
     * @return array<string,mixed> Closed payload: health, version, exception_count.
     */
    public function buildPayload(array $healthStatus, string $version, int $exceptionCount): array
    {
        return [
            'health' => $healthStatus,
            'version' => $version,
            'exception_count' => $exceptionCount,
        ];
    }
}
