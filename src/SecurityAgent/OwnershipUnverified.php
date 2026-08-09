<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use RuntimeException;

/**
 * Raised when an authorization is asked to become active without an approved,
 * evidenced ownership proof (SBR-3.2).
 *
 * A dedicated type rather than a generic exception: the activation path must
 * be able to fail for this reason SPECIFICALLY, and a caller catching it is
 * making a deliberate choice about an authority failure rather than swallowing
 * "something went wrong".
 *
 * © AI WebScapes 2026
 */
final class OwnershipUnverified extends RuntimeException
{
    /**
     * @param list<string> $approved
     */
    public static function forProof(int $authorizationId, string $proofType, array $approved): self
    {
        return new self(sprintf(
            'Authorization %d cannot become active: ownership proof "%s" is not an approved method '
            . '(SBR-3.2). Approved methods: %s.',
            $authorizationId,
            $proofType === '' ? '(none recorded)' : $proofType,
            implode(', ', $approved)
        ));
    }
}
