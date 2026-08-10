<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use RuntimeException;

/**
 * Thrown when assembled report content still carries a secret or a session
 * token, so the report is refused rather than emitted.
 *
 * THE ACCEPTANCE TEST THIS ENFORCES, VERBATIM
 * --------------------------------------------
 * FRD section 7, "Report redaction" row: "Secrets and session tokens are
 * absent from normal report output."
 *
 * And the requirement behind it:
 *
 *   SFR-AUTH-003 [Must] Credentials shall be stored as scoped secrets and
 *                never included in reports or logs.
 *
 * WHY REFUSE RATHER THAN REDACT-AND-CONTINUE
 * -------------------------------------------
 * The evidence layer redacts at the point of capture (SFR-EVID-002), so by the
 * time content reaches a report it has already passed a redaction gate. A
 * secret arriving HERE therefore means an upstream control did not hold, and
 * the safe response to "a control I rely on has failed" is to stop, not to
 * paper over the symptom and ship a report that looks clean.
 *
 * Silently scrubbing at the last moment would also destroy the signal: nobody
 * would ever learn that evidence redaction had a hole, because every report
 * would come out tidy. This exception is the alarm.
 *
 * OWASP ASVS 5.0 V16.5.3 puts the same rule generally — fail gracefully and
 * securely, "preventing fail-open conditions" — and V16.2.5 sets the
 * data-handling bar this gate enforces: credentials may not be emitted at all,
 * and session tokens only hashed or masked.
 *
 * WHY AN EXCEPTION AND NOT A FILTERED RESULT. Same reasoning as
 * ClosureEvidenceRequired: a returned bool or a quietly-shortened array is a
 * result a caller may ignore, and the caller wants the report. A thrown
 * refusal fails closed — no report object exists to be exported.
 *
 * Carries the KINDS found (never the offending value itself — that would put
 * the secret into the exception message, and from there into a log, which is
 * the very thing SFR-AUTH-003 forbids) and the field that carried them.
 *
 * © AI WebScapes 2026
 */
final class ReportRedactionRequired extends RuntimeException
{
    /**
     * @param list<string> $kinds The RedactionScanner kinds detected, e.g.
     *                            ['secret', 'session_token']. Kinds only —
     *                            never the value.
     */
    public function __construct(
        private readonly array $kinds,
        private readonly string $field,
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Which kinds of sensitive data were found.
     *
     * @return list<string>
     */
    public function kinds(): array
    {
        return $this->kinds;
    }

    /**
     * The report field that carried them. A field name is safe to log; its
     * value is not.
     */
    public function field(): string
    {
        return $this->field;
    }
}
