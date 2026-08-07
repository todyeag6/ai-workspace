<?php

declare(strict_types=1);

namespace App\AI;

/**
 * The seam between the gateway and whatever actually runs the model.
 *
 * WHY THE WHOLE REQUEST AND NOT JUST A PROMPT: FR-AI-002 says a model call
 * specifies model/version, timeout, tenant and data classification. If the
 * adapter only received a prompt string, every one of those would have to be
 * re-supplied out of band - and the one that matters most operationally, the
 * timeout, would end up hard-coded inside each adapter where no caller can see
 * it. Passing AIRequest keeps the metadata and the call inseparable.
 *
 * The interface is deliberately one method wide and returns a plain string:
 * decoding, validating and dispositioning belong to AIGateway, so an adapter
 * cannot quietly become the thing that decides an output is acceptable.
 *
 * Concrete adapters (local Ollama, hosted APIs) are P1-T7. This file only
 * fixes the shape they must fit.
 *
 * © AI WebScapes 2026
 */
interface ModelAdapter
{
    /**
     * Runs the model and returns its raw, undecoded output.
     *
     * Implementations MUST honour $request->timeoutSeconds() and MUST NOT
     * retry silently: a retry doubles the token spend the gateway just
     * authorised against the request's budget.
     */
    public function generate(AIRequest $request): string;
}
