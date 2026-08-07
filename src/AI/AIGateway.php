<?php

declare(strict_types=1);

namespace App\AI;

/**
 * The single door between this platform and a language model (P1-T6).
 *
 * Three properties are structural rather than advisory:
 *
 *   1. NO CALL WITHOUT METADATA (FR-AI-002). complete() takes an AIRequest and
 *      nothing else, and an AIRequest cannot exist without model/version,
 *      config version, purpose, tenant, data classification, token and cost
 *      limits, timeout and an expected output schema. There is no overload
 *      that accepts a bare prompt, so the metadata cannot be skipped in a
 *      hurry.
 *
 *   2. BUDGET FIRST (FR-AI-002). The token and cost checks run BEFORE the
 *      adapter is touched, so an over-budget call costs nothing. Checking
 *      afterwards would report the overspend accurately and still have spent
 *      it.
 *
 *   3. NO SIDE EFFECT ON INVALID OUTPUT (FR-AI-003, AC-003). An output that
 *      fails its schema returns disposition 'review' with no payload. This is
 *      guaranteed by CONSTRUCTION, not by discipline: the gateway holds a
 *      ModelAdapter and a SchemaValidator and nothing else - no PDO, no
 *      mailer, no tool gateway, no HTTP client - so there is no effect
 *      available for it to fire on any path. AIGatewayTest asserts that
 *      dependency list reflectively, so adding an effectful collaborator here
 *      fails the AC-003 test rather than quietly widening the blast radius.
 *
 * WHAT THIS CLASS DELIBERATELY DOES NOT DO: it does not act on the payload. A
 * valid result is returned to the caller, who owns the decision to write, send
 * or call anything. Acting on model output belongs behind the tool gateway and
 * its authorisation rules (P1-T7/T8), and merging the two would put "decide
 * whether the output is safe" and "do the thing" in one class where the second
 * could not be prevented independently of the first.
 *
 * © AI WebScapes 2026
 */
final class AIGateway
{
    public function __construct(
        private readonly ModelAdapter $adapter,
        private readonly SchemaValidator $validator
    ) {
    }

    /**
     * Runs one fully specified model call and returns a dispositioned result.
     *
     * @throws BudgetExceeded When the call would exceed the token or cost
     *                        limit the request itself declared. Thrown before
     *                        the model is reached.
     */
    public function complete(AIRequest $request): AIResult
    {
        $this->assertWithinBudget($request);

        $raw = $this->adapter->generate($request);

        $decoded = json_decode($raw, true);

        if (!is_array($decoded)) {
            // Not even JSON: fails safe exactly like a schema mismatch. The
            // distinction matters to a reviewer, not to the safety property.
            return AIResult::review($raw, [sprintf(
                'output was not a JSON object (%s)',
                json_last_error() === JSON_ERROR_NONE ? get_debug_type($decoded) : json_last_error_msg()
            )]);
        }

        $errors = $this->validator->errors($decoded, $request->outputSchema());

        if ($errors !== []) {
            return AIResult::review($raw, $errors);
        }

        return AIResult::accepted($decoded, $raw);
    }

    /**
     * FR-AI-002's token and cost limits, enforced while refusing is still
     * free.
     */
    private function assertWithinBudget(AIRequest $request): void
    {
        if ($request->promptTokens() > $request->tokenLimit()) {
            throw BudgetExceeded::tokens(
                $request->purpose(),
                $request->promptTokens(),
                $request->tokenLimit()
            );
        }

        $estimated = $request->estimatedCostCents();

        if ($estimated > $request->costLimitCents()) {
            throw BudgetExceeded::cost(
                $request->purpose(),
                $estimated,
                $request->costLimitCents()
            );
        }
    }
}
