<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Audit\AuditLogger;
use App\Data\TenantRepository;
use JsonException;
use PDO;
use RuntimeException;

/**
 * Tenant-scoped persistence for scan profiles - the approved safety envelope
 * (SFR-SAFE-001, SFR-SAFE-003, SBR-3.3).
 *
 * THREE THINGS THIS CLASS REFUSES TO DO
 * -------------------------------------
 *   1. It never creates an APPROVED destructive profile. create() has no
 *      argument that could set destructive_approved - approval is a separate
 *      act by a separate caller (SFR-SAFE-003), and a method signature that
 *      offered both at once would make "separately approved" a formality.
 *   2. It never approves what was not enabled. approveDestructiveChecks()
 *      refuses a profile whose destructive checks are off, because approving
 *      one would be a way to turn destructive behaviour on through the
 *      approval path rather than the authoring path.
 *   3. It never edits a frozen envelope. Once a scan has run under a profile
 *      it is marked immutable (SFR-SCAN-001) and further changes are refused,
 *      so a completed report cannot be re-interpreted by editing the limits it
 *      ran under.
 *
 * VALIDATE BEFORE EFFECT, then EVIDENCE. Same ordering as
 * AuthorizationRepository::activate(): every precondition is checked before
 * the write, and the approval is audited after it succeeds, so the trail never
 * claims an approval the database refused.
 *
 * AC-001 comes from the base class: construction builds a TenantScope, and
 * every statement carries `tenant_id = :tenant` bound internally.
 *
 * © AI WebScapes 2026
 */
final class ScanProfileRepository extends TenantRepository
{
    public const AUDIT_APPROVE = 'secscan.destructive.approve';

    private const AUDIT_SOURCE = 'scan_profile_repository';

    private const AUDIT_OBJECT_TYPE = 'scan_profile';

    private ?AuditLogger $audit;

    /**
     * @param AuditLogger|null $audit Required only for approveDestructiveChecks(),
     *                                which refuses to run unevidenced.
     */
    public function __construct(PDO $pdo, ?int $tenantId, ?AuditLogger $audit = null)
    {
        parent::__construct($pdo, $tenantId);

        $this->audit = $audit;
    }

    protected function table(): string
    {
        return 'scan_profiles';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'authorization_id',
            'version',
            'checks',
            'destructive_checks_enabled',
            'destructive_approved',
            'concurrency_limit',
            'rate_limit_per_min',
            'request_timeout_sec',
            'max_payload_bytes',
            'max_retries',
            'max_duration_sec',
            'immutable_after_use',
            'created_at',
        ];
    }

    /**
     * Records a new profile.
     *
     * DEFAULTS ARE THE REQUIREMENT, NOT A CONVENIENCE. SBR-3.3 says default
     * scans are non-destructive and rate-limited; SFR-SAFE-003 says
     * destructive checks are disabled by default. A caller that passes nothing
     * but the checks therefore gets a safe profile, and getting an unsafe one
     * takes a deliberate argument.
     *
     * There is deliberately no $destructiveApproved parameter: see the class
     * comment.
     *
     * @param array<array-key, string> $checks The check identifiers this profile runs.
     */
    public function create(
        int $authorizationId,
        array $checks,
        bool $destructiveChecksEnabled = false,
        int $concurrencyLimit = 1,
        int $rateLimitPerMin = 60,
        int $requestTimeoutSec = 30,
        int $maxPayloadBytes = 1048576,
        int $maxRetries = 3,
        int $maxDurationSec = 3600,
        int $version = 1
    ): int {
        $this->assertPositive($concurrencyLimit, 'concurrency_limit');
        $this->assertPositive($rateLimitPerMin, 'rate_limit_per_min');
        $this->assertPositive($requestTimeoutSec, 'request_timeout_sec');
        $this->assertPositive($maxPayloadBytes, 'max_payload_bytes');
        $this->assertPositive($maxDurationSec, 'max_duration_sec');

        if ($maxRetries < 0) {
            throw new RuntimeException('max_retries cannot be negative.');
        }

        return (int) $this->insertScoped([
            'authorization_id' => $authorizationId,
            'version' => $version,
            'checks' => $this->encodeChecks($checks),
            'destructive_checks_enabled' => $destructiveChecksEnabled ? 1 : 0,
            // Never approved at creation: SFR-SAFE-003 requires a separate act.
            'destructive_approved' => 0,
            'concurrency_limit' => $concurrencyLimit,
            'rate_limit_per_min' => $rateLimitPerMin,
            'request_timeout_sec' => $requestTimeoutSec,
            'max_payload_bytes' => $maxPayloadBytes,
            'max_retries' => $maxRetries,
            'max_duration_sec' => $maxDurationSec,
            'immutable_after_use' => 0,
        ]);
    }

    /**
     * The separate approval required by SFR-SAFE-003.
     *
     * ORDER IS THE DESIGN: the profile must exist in this tenant, must have
     * destructive checks ENABLED (you cannot approve what is not there), and
     * must not be frozen. Only then is the flag written, and only then is the
     * approval recorded - naming the approver, so the sign-off has an owner.
     *
     * @throws RuntimeException When the profile is absent, non-destructive or frozen.
     */
    public function approveDestructiveChecks(int $id, int $approverUserId): void
    {
        $profile = $this->requireById($id);

        if (!$profile->isDestructiveEnabled()) {
            throw new RuntimeException(sprintf(
                'Scan profile %d does not enable destructive checks, so there is nothing to '
                . 'approve (SFR-SAFE-003).',
                $id
            ));
        }

        if ($profile->isImmutable()) {
            throw new RuntimeException(sprintf(
                'Scan profile %d has already been used by a scan and is frozen (SFR-SCAN-001).',
                $id
            ));
        }

        $this->updateScoped(['destructive_approved' => 1], 'id = :id', ['id' => $id]);

        $this->requireAudit()->record(
            $this->tenantId(),
            $approverUserId,
            self::AUDIT_APPROVE,
            self::AUDIT_OBJECT_TYPE,
            (string) $id,
            // audit_events.outcome is ENUM('success','failure','denied'); the
            // WHAT lives in the action, the outcome says only how it ended.
            'success',
            self::AUDIT_SOURCE,
            null,
            [],
            [],
            'destructive checks approved for profile ' . $id
        );
    }

    /**
     * Freezes the envelope once a scan has used it (SFR-SCAN-001). After this
     * the profile is a historical record: a new version is authored instead of
     * editing it.
     */
    public function markImmutable(int $id): bool
    {
        $this->requireById($id);

        return $this->updateScoped(['immutable_after_use' => 1], 'id = :id', ['id' => $id]) > 0;
    }

    /**
     * Null both when the profile does not exist and when it belongs to another
     * tenant - deliberately indistinguishable (AC-001).
     */
    public function findById(int $id): ?ScanProfile
    {
        $rows = $this->selectScoped('id = :id', ['id' => $id]);
        if ($rows === []) {
            return null;
        }

        return ScanProfile::fromRow($rows[0]);
    }

    /**
     * @throws RuntimeException When no such profile exists in this tenant.
     */
    public function requireById(int $id): ScanProfile
    {
        $profile = $this->findById($id);
        if ($profile === null) {
            throw new RuntimeException(sprintf(
                'Scan profile %d does not exist for tenant %d.',
                $id,
                $this->tenantId()
            ));
        }

        return $profile;
    }

    /**
     * @param array<array-key, string> $checks
     */
    private function encodeChecks(array $checks): string
    {
        try {
            return json_encode(array_values($checks), JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('The scan profile check list could not be encoded.', 0, $e);
        }
    }

    /**
     * A limit of zero or less is not a limit, and storing one would leave the
     * SafetyMonitor enforcing nothing (SFR-SAFE-001). Refused at the boundary.
     */
    private function assertPositive(int $value, string $name): void
    {
        if ($value <= 0) {
            throw new RuntimeException(sprintf(
                'Scan profile limit "%s" must be positive; a non-positive limit would leave '
                . 'the safety envelope unenforced (SFR-SAFE-001).',
                $name
            ));
        }
    }

    private function requireAudit(): AuditLogger
    {
        if ($this->audit === null) {
            // Fail closed: an approval nobody can evidence is not an approval.
            throw new RuntimeException(
                'An AuditLogger must be injected before destructive checks can be approved '
                . '(SFR-SAFE-003).'
            );
        }

        return $this->audit;
    }
}
