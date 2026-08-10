<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use RuntimeException;

/**
 * Thrown when evidence carries sensitive material and redaction was not
 * permitted (SFR-EVID-002, fail-closed).
 *
 * Carries the LIST OF KINDS that were found so the caller can report exactly
 * what must be redacted before the item may be stored - the refusal is
 * actionable, not a bare "no".
 *
 * © AI WebScapes 2026
 */
final class EvidenceRedactionRequired extends RuntimeException
{
    /**
     * @param list<string> $kinds The sensitive kinds detected (e.g. secret,
     *                            session_token, personal_data, response_body).
     */
    public function __construct(
        private readonly array $kinds,
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * @return list<string>
     */
    public function kinds(): array
    {
        return $this->kinds;
    }
}
