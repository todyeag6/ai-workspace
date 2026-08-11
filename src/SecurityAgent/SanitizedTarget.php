<?php

declare(strict_types=1);

namespace App\SecurityAgent;

/**
 * The validated, safe-to-pass-as-an-operand scan target (SFR-SELF-005).
 *
 * Produced by App\SecurityAgent\TargetSanitizer::sanitize() and consumed by
 * App\SecurityAgent\SafeScannerInvoker, which appends it after a POSIX "--"
 * delimiter as a single argv element. It is an immutable value object: the
 * canonical form is what the scanner receives, and the host is what was
 * range-checked, so the invoker never re-parses the original hostile string.
 *
 * © AI WebScapes 2026
 */
final class SanitizedTarget
{
    public function __construct(
        public readonly string $canonical,
        public readonly string $host,
    ) {
    }
}
