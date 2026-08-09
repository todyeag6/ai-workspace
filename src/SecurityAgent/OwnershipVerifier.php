<?php

declare(strict_types=1);

namespace App\SecurityAgent;

/**
 * Verifies ownership or delegated authority before active testing
 * (SBR-3.2: "the service shall verify ownership or delegated authority using
 * an approved method before active testing").
 *
 * ALLOWLIST, NOT DENYLIST (AC-002). The question this class answers is "is the
 * recorded proof one of the methods we approved", not "does the proof look
 * suspicious". A method nobody approved is refused by default, so adding a new
 * proof type is a deliberate edit here rather than an omission somewhere else.
 *
 * A REFERENCE IS ALSO REQUIRED. An approved TYPE with an empty REF is a claim
 * with no evidence behind it - "we did a DNS check" with no record of which
 * record was seen. Both halves must be present.
 *
 * STATED LIMIT: this verifies that an approved method was RECORDED, not that
 * the DNS record still resolves today. Live re-validation is a network action
 * and belongs to the scanner, not to a pure decision class - the same
 * decides-does-not-act split as App\Tools\ToolGateway. What this class
 * guarantees is that no authorization becomes active without an approved,
 * evidenced method on file.
 *
 * © AI WebScapes 2026
 */
final class OwnershipVerifier
{
    /**
     * The approved methods. Each is an out-of-band proof the client must
     * perform: a DNS TXT record only the domain owner can publish, a reply
     * from a mailbox at the domain, a signed authorization letter, or a
     * delegated-authority contract for third-party-managed estates.
     *
     * @var list<string>
     */
    public const APPROVED_METHODS = [
        'dns-txt',
        'email-domain',
        'signed-letter',
        'delegated-contract',
    ];

    public function verify(Authorization $authorization): bool
    {
        return $this->isApprovedMethod($authorization->ownershipProofType())
            && trim($authorization->ownershipProofRef()) !== '';
    }

    /**
     * The throwing form, for the activation path where "false" must stop the
     * transition rather than be returned to a caller who might ignore it.
     *
     * @throws OwnershipUnverified
     */
    public function assertVerified(Authorization $authorization): void
    {
        if (!$this->verify($authorization)) {
            throw OwnershipUnverified::forProof(
                $authorization->id(),
                $authorization->ownershipProofType(),
                self::APPROVED_METHODS
            );
        }
    }

    private function isApprovedMethod(string $type): bool
    {
        return in_array(strtolower(trim($type)), self::APPROVED_METHODS, true);
    }
}
