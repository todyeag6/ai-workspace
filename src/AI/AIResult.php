<?php

declare(strict_types=1);

namespace App\AI;

/**
 * The outcome of one model call: whether the output matched its declared
 * schema, what disposition that earns it, the validated payload (only when
 * valid) and the raw text the model actually produced.
 *
 * WHY payload IS null WHEN INVALID: the failure mode FR-AI-003 exists to stop
 * is downstream code reading a field out of an output nobody checked. If an
 * invalid result still carried a payload, "check valid first" would be a
 * convention - and conventions are followed right up until the one call site
 * that forgets. Here there is nothing to read, so the mistake is not
 * expressible.
 *
 * WHY raw IS KEPT ON BOTH PATHS: an output going to review is useless to the
 * reviewer without the text that failed, and on the valid path it is the
 * evidence that the payload was not synthesised.
 *
 * Named constructors rather than a public constructor: a result is either
 * accepted or under review, and there is no third combination of these fields
 * worth being able to build.
 *
 * © AI WebScapes 2026
 */
final class AIResult
{
    public const DISPOSITION_ACTIVE = 'active';
    public const DISPOSITION_REVIEW = 'review';

    /**
     * @param array<array-key, mixed>|null $payload
     * @param list<string>                 $errors
     */
    private function __construct(
        public readonly bool $valid,
        public readonly string $disposition,
        public readonly ?array $payload,
        public readonly string $raw,
        public readonly array $errors
    ) {
    }

    /**
     * @param array<array-key, mixed> $payload
     */
    public static function accepted(array $payload, string $raw): self
    {
        return new self(true, self::DISPOSITION_ACTIVE, $payload, $raw, []);
    }

    /**
     * The fail-safe direction (FR-AI-003, AC-003): no payload, no downstream
     * use, and the reasons recorded so a human can see what the model did.
     *
     * @param list<string> $errors
     */
    public static function review(string $raw, array $errors): self
    {
        return new self(false, self::DISPOSITION_REVIEW, null, $raw, $errors);
    }
}
