<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use RuntimeException;
use Throwable;

/**
 * Thrown when target-derived content cannot be safely placed in front of a
 * model, so no model call is made at all (SFR-AI-002, fail closed).
 *
 * WHY A THROW AND NOT A DEGRADED CALL. SFR-AI-002 says untrusted target
 * content "shall be treated as data and shall not control the AI system or
 * invoke tools". Every condition that raises this exception is a case where
 * that property could not be established BEFORE the call — quarantine could
 * not be sealed, a live directive survived outside it, the content still
 * carries unredacted secrets, or it is simply too large to reason about. The
 * safe response to "I cannot prove this is inert" is not to send it anyway
 * with a warning attached; it is to not send it.
 *
 * Carries the REASON as a stable machine-readable code plus the human detail,
 * so an operator sees which property failed rather than a bare "no", and a
 * caller can audit the refusal (SFR-AUD-001) without string-matching a
 * message.
 *
 * © AI WebScapes 2026
 */
final class UntrustedContentRefused extends RuntimeException
{
    /** Content still carried sensitive material (SFR-EVID-002, SFR-SELF-004). */
    public const REASON_UNREDACTED = 'unredacted_content';

    /** A tool directive was live OUTSIDE quarantine after assembly. */
    public const REASON_LIVE_DIRECTIVE = 'live_tool_directive';

    /** More attacker-controlled text than the policy admits in one prompt. */
    public const REASON_OVERSIZED = 'oversized_untrusted_content';

    /** The model's own output carried a tool directive (unsafe output). */
    public const REASON_UNSAFE_OUTPUT = 'unsafe_model_output';

    /**
     * @param string       $reason  One of the REASON_* codes above.
     * @param list<string> $details Supporting facts (e.g. detected redaction
     *                              kinds). Never the offending content itself:
     *                              a refusal must not become the mechanism by
     *                              which the payload is copied into a log.
     */
    public function __construct(
        private readonly string $reason,
        private readonly array $details = [],
        string $message = '',
        int $code = 0,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    public function reason(): string
    {
        return $this->reason;
    }

    /**
     * @return list<string>
     */
    public function details(): array
    {
        return $this->details;
    }
}
