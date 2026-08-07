<?php

declare(strict_types=1);

namespace App\Data;

/**
 * Outcome of a verified deletion (FR-DATA-002).
 *
 * @property-read int  $deleted         Rows removed.
 * @property-read bool $verified        True only when the erasure was re-counted to zero.
 * @property-read int  $verificationId  The recorded proof row, or 0 when verification was not requested.
 */
final class DeletionResult
{
    public function __construct(
        public readonly int $deleted,
        public readonly bool $verified,
        public readonly int $verificationId = 0
    ) {
    }
}
