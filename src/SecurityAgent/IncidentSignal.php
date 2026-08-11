<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Audit\AuditLogger;

/**
 * SFR-SELF-006 - audited signal on scanner refusal.
 *
 * SFR-SELF-006 [Must] requires the service to "maintain incident procedures
 * for accidental out-of-scope traffic, service degradation, credential
 * exposure, and evidence leakage." The existing runbook
 * (docs/INCIDENT_RESPONSE.md) already covers those four scenarios; this class
 * closes the gap between a *refusal* (which the guards throw) and a *recorded
 * event the procedure can act on*. When a scanner target is refused - most
 * starkly for "accidental out-of-scope traffic" - the refusal is emitted as an
 * immutable audit event, not just a thrown exception. That makes the incident
 * measurable (NIST AI RMF 1.0, Measure/Manage functions expect auditable
 * incident handling for AI-specific failures such as data leakage / scope
 * pivot).
 *
 * THIS CLASS IS THE ACTOR; THE GUARD DECIDES. It performs no validation of its
 * own - it is handed a refusal reason code and records it. The decision (refuse
 * or not) lives entirely in TargetSanitizer / ScannerInfrastructureGuard.
 *
 * WHY object_id IS A SHORT REASON CODE, NOT THE TARGET STRING: AuditLogger
 * redacts any 16+ char high-entropy blob in the free-text detail (SFR-AUTH-003
 * defence in depth). A hostile target ("https://app.client.test/;rm -rf /")
 * would be scrubbed there, so we assert identity against the bounded,
 * stable object_id (e.g. "self005:cmd-injection") instead. The detail carries
 * only a non-secret, bounded reason.
 *
 * © AI WebScapes 2026
 */
final class IncidentSignal
{
    public function __construct(private readonly AuditLogger $audit)
    {
    }

    /**
     * Emits an immutable audit event for a scanner refusal.
     *
     * @param int    $tenantId   The tenant scope the scan was attempted under.
     * @param string $reasonCode Bounded, stable code (e.g. "self001:prod-scope",
     *                           "self005:cmd-injection"). Survives redaction.
     * @param string $outcome    'denied' (the audit_events.outcome ENUM; a refusal
     *                           is a denied action - 'success'/'failure'/'denied').
     * @param array<mixed> $payload Structured context (already free of secrets).
     */
    public function scanRefused(
        int $tenantId,
        string $reasonCode,
        string $outcome,
        array $payload = []
    ): int {
        return $this->audit->record(
            $tenantId,
            null,
            'scanner.scan_refused',
            'scanner_target',
            $reasonCode,
            $outcome,
            'security_agent',
            null,
            [],
            $payload,
            'Scanner target refused under SFR-SELF guard.'
        );
    }
}
