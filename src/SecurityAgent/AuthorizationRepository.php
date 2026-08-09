<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Data\TenantRepository;
use DateTimeImmutable;
use JsonException;
use PDO;
use RuntimeException;

/**
 * Tenant-scoped persistence for engagement authorizations and the scope list
 * they carry (SFR-AUTH-001/003, SBR-3.1/3.2).
 *
 * THREE THINGS THIS CLASS REFUSES TO DO
 * -------------------------------------
 *   1. It never returns a raw row. Every read hands back an Authorization
 *      value object, which has no credential property at all - so ciphertext
 *      read from the table cannot escape the repository by accident
 *      (SFR-AUTH-003). The one deliberate exit is credential(), which
 *      decrypts and is named so that its use is visible in review.
 *   2. It never writes a plaintext credential. create() encrypts through the
 *      injected ScopedSecretStore and stores ciphertext plus a one-way
 *      fingerprint; there is no column that could hold the plaintext.
 *   3. It never makes an authorization active by itself. activate() is the
 *      only transition to 'active', and it runs OwnershipVerifier (SBR-3.2)
 *      and the completeness check (SBR-3.1) BEFORE the update - the same
 *      validate-before-effect ordering App\Tools\ToolGateway uses.
 *
 * AC-001 comes from the base class: construction builds a TenantScope, and
 * every statement carries `tenant_id = :tenant` bound internally.
 *
 * © AI WebScapes 2026
 */
final class AuthorizationRepository extends TenantRepository
{
    private ScanTargetRepository $targets;

    private OwnershipVerifier $ownership;

    private ?ScopedSecretStore $secrets;

    /**
     * @param ScopedSecretStore|null $secrets Required only when a credential is
     *                                        stored or read. The key is injected
     *                                        into the store by the composition
     *                                        root - this class never reads the
     *                                        environment for one.
     */
    public function __construct(
        PDO $pdo,
        ?int $tenantId,
        ?ScopedSecretStore $secrets = null,
        ?OwnershipVerifier $ownership = null
    ) {
        parent::__construct($pdo, $tenantId);

        // Built here rather than injected so a caller cannot hand in a target
        // repository scoped to a different tenant.
        $this->targets = new ScanTargetRepository($pdo, $tenantId);
        $this->secrets = $secrets;
        $this->ownership = $ownership ?? new OwnershipVerifier();
    }

    protected function table(): string
    {
        return 'security_authorizations';
    }

    /**
     * credentials_ciphertext is selected because credential() needs it, and
     * NOT because anything else may see it: no public method returns a raw
     * row, so the column's only exit is the decrypting accessor.
     *
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'client_name',
            'status',
            'valid_from',
            'valid_to',
            'technique_profile',
            'stop_contact',
            'ownership_proof_type',
            'ownership_proof_ref',
            'credentials_ciphertext',
            'credentials_fingerprint',
            'created_by',
            'created_at',
        ];
    }

    /**
     * Records a new authorization as a DRAFT.
     *
     * Draft, always: SBR-3.2 requires verified ownership before active
     * testing, so there is no argument to this method that could produce an
     * active row.
     *
     * @param array<array-key, string> $techniqueProfile The agreed technique envelope. Declared
     *                                                   loosely because this is the boundary that
     *                                                   normalises caller input into a JSON list.
     * @param string|null              $credential       Plaintext, encrypted here and never stored
     *                                                   as given.
     */
    public function create(
        string $clientName,
        array $techniqueProfile,
        string $stopContact,
        string $ownershipProofType,
        string $ownershipProofRef,
        ?DateTimeImmutable $validFrom = null,
        ?DateTimeImmutable $validTo = null,
        ?string $credential = null,
        ?int $createdBy = null
    ): int {
        $ciphertext = null;
        $fingerprint = null;

        if ($credential !== null && $credential !== '') {
            $store = $this->requireStore();
            $ciphertext = $store->encrypt($credential);
            $fingerprint = $store->fingerprint($credential);
        }

        return (int) $this->insertScoped([
            'client_name' => $clientName,
            'status' => 'draft',
            'valid_from' => $validFrom?->format('Y-m-d H:i:s'),
            'valid_to' => $validTo?->format('Y-m-d H:i:s'),
            'technique_profile' => $this->encodeProfile($techniqueProfile),
            'stop_contact' => $stopContact,
            'ownership_proof_type' => $ownershipProofType,
            'ownership_proof_ref' => $ownershipProofRef,
            'credentials_ciphertext' => $ciphertext,
            'credentials_fingerprint' => $fingerprint,
            'created_by' => $createdBy,
        ]);
    }

    /**
     * The only transition to 'active'.
     *
     * ORDER IS THE DESIGN: ownership first (SBR-3.2 - authority is the
     * precondition for testing at all), completeness second (SBR-3.1 - the
     * record must carry timing, contacts and technique envelope), and only
     * then the write. A failure leaves the row untouched.
     *
     * @throws OwnershipUnverified     Proof method is not approved, or unevidenced.
     * @throws IncompleteAuthorization A mandatory element is missing.
     */
    public function activate(int $id): void
    {
        $authorization = $this->requireById($id);

        $this->ownership->assertVerified($authorization);

        if (!$authorization->isComplete()) {
            throw IncompleteAuthorization::forId($id);
        }

        $this->updateScoped(['status' => 'active'], 'id = :id', ['id' => $id]);
    }

    /**
     * Ends an authorization early (a stop condition being exercised, or the
     * client withdrawing consent). A revoked authorization can never be active
     * again - a new one is recorded instead, so the trail stays honest.
     */
    public function revoke(int $id): void
    {
        $this->requireById($id);
        $this->updateScoped(['status' => 'revoked'], 'id = :id', ['id' => $id]);
    }

    /**
     * Null both when the authorization does not exist and when it belongs to
     * another tenant - deliberately indistinguishable (AC-001).
     */
    public function findById(int $id): ?Authorization
    {
        $rows = $this->selectScoped('id = :id', ['id' => $id]);
        if ($rows === []) {
            return null;
        }

        return Authorization::fromRow($rows[0]);
    }

    /**
     * @throws RuntimeException When no such authorization exists in this tenant.
     */
    public function requireById(int $id): Authorization
    {
        $authorization = $this->findById($id);
        if ($authorization === null) {
            throw new RuntimeException(sprintf(
                'Authorization %d does not exist for tenant %d.',
                $id,
                $this->tenantId()
            ));
        }

        return $authorization;
    }

    /**
     * Adds an in-scope (or explicitly excluded) target to an authorization.
     *
     * requireById() runs first so a target cannot be attached to another
     * tenant's authorization id: the scan_targets row would carry OUR tenant
     * while pointing at THEIR authorization, which is exactly the cross-tenant
     * confusion AC-001 forbids.
     */
    public function addTarget(
        int $authorizationId,
        string $rawTarget,
        bool $inScope = true,
        bool $excluded = false
    ): int {
        $this->requireById($authorizationId);

        return $this->targets->add($authorizationId, $rawTarget, $inScope, $excluded);
    }

    /**
     * SFR-AUTH-002, the per-request question. $canonicalTarget must already be
     * canonical - ScopeManager canonicalizes before asking.
     */
    public function isTargetInScope(int $authorizationId, string $canonicalTarget): bool
    {
        return $this->targets->isInScope($authorizationId, $canonicalTarget);
    }

    /**
     * The agreed scope, for reporting it back to the client.
     *
     * @return list<array<string, scalar|null>>
     */
    public function targetsFor(int $authorizationId): array
    {
        return $this->targets->forAuthorization($authorizationId);
    }

    /**
     * The one deliberate exit for credential material (SFR-AUTH-003). Named so
     * that any call site is obvious in review; nothing in the reporting path
     * calls it, and the plaintext is never returned by any other method.
     */
    public function credential(int $id): ?string
    {
        $rows = $this->selectScoped('id = :id', ['id' => $id]);
        if ($rows === []) {
            return null;
        }

        $ciphertext = $rows[0]['credentials_ciphertext'] ?? null;
        if (!is_string($ciphertext) || $ciphertext === '') {
            return null;
        }

        return $this->requireStore()->decrypt($ciphertext);
    }

    /**
     * @param array<array-key, string> $techniqueProfile
     */
    private function encodeProfile(array $techniqueProfile): string
    {
        try {
            return json_encode(array_values($techniqueProfile), JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('The technique profile could not be encoded.', 0, $e);
        }
    }

    private function requireStore(): ScopedSecretStore
    {
        if ($this->secrets === null) {
            // Fail closed: without a store there is no way to encrypt, and
            // storing the plaintext instead is not an available fallback.
            throw new RuntimeException(
                'A ScopedSecretStore must be injected before credentials can be stored or read '
                . '(SFR-AUTH-003).'
            );
        }

        return $this->secrets;
    }
}
