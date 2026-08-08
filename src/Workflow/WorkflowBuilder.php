<?php

declare(strict_types=1);

namespace App\Workflow;

use InvalidArgumentException;

/**
 * Builds and validates a WorkflowDefinition (P2-T3 "workflow builder").
 *
 * WHY A BUILDER AND NOT A CONSTRUCTOR ON THE DEFINITION: a definition is
 * immutable and therefore cannot self-validate a growing list without either
 * taking a raw array and silently coercing it (defeating the point) or
 * exposing setters (breaking immutability). The builder holds the partial,
 * mutable view during assembly and returns a validated, frozen
 * WorkflowDefinition via build().
 *
 * WHAT IT REFUSES (all caught at authoring, none at charge time):
 *   1. Unknown step type - only the engine's executable types are allowed
 *      ('charge', 'reserve_stock', the 'fail' trigger). A typo would otherwise
 *      sail into the Orchestrator and be performed with no compensation map.
 *   2. Unknown risk class - 'low' | 'medium' | 'high' | 'critical' only. The
 *      engine treats an unrecognised risk as high (fail-closed), so a misspelt
 *      class would silently escalate a step to high-impact. The builder refuses
 *      the misspelling instead, so the author sees their error.
 *   3. High|critical step without an approver id - FR-ORCH-003 / FR-AI-006 say
 *      such a step needs a recorded human before it can run. The builder flags
 *      the definition requiresApproval=true; the caller must route it through
 *      Orchestrator::approve() first. We do not *store* the approver here - that
 *      is the engine's job at run time - we only refuse to build a definition
 *      that would be unexecutable without one.
 *   4. Duplicate step keys - a step list with two 'charge' steps would produce
 *      two identical idempotency keys (the engine keys on workflow+index+type),
 *      so the second would always be "skipped" as a replay of the first. The
 *      builder requires distinct step types within a definition.
 *
 * The set of known step types is mirrored from Orchestrator::COMPENSATIONS plus
 * the 'fail' trigger, kept here so authoring fails closed on the same vocabulary
 * the runtime executes.
 *
 * © AI WebScapes 2026
 */
final class WorkflowBuilder
{
    /** @var array<string, string> Step type => compensation (mirrors engine). */
    private const KNOWN_STEPS = [
        'charge' => 'refund',
        'reserve_stock' => 'release_stock',
        'fail' => '',
    ];

    /** @var list<string> */
    private const RISK_CLASSES = ['low', 'medium', 'high', 'critical'];

    /** @var list<string> */
    private const HIGH_IMPACT = ['high', 'critical'];

    /**
     * @param list<array<string, mixed>> $steps Raw, untrusted step list. The
     *                                      builder validates every entry; the
     *                                      type is intentionally loose because
     *                                      validation is this class's job.
     */
    public function __construct(
        private readonly string $workflowId,
        private readonly array $steps
    ) {
    }

    public function build(): WorkflowDefinition
    {
        if ($this->workflowId === '') {
            throw new InvalidArgumentException('A workflow definition requires a non-empty workflow id.');
        }
        if ($this->steps === []) {
            throw new InvalidArgumentException('A workflow definition requires at least one step.');
        }

        $normalised = [];
        $seenTypes = [];
        $requiresApproval = false;

        foreach ($this->steps as $index => $step) {
            if (!isset($step['type']) || !is_string($step['type'])) {
                throw new InvalidArgumentException(sprintf(
                    'Step %d is missing a string "type".',
                    $index
                ));
            }

            $type = $step['type'];
            if (!array_key_exists($type, self::KNOWN_STEPS)) {
                throw new InvalidArgumentException(sprintf(
                    'Unknown workflow step type "%s" at step %d. Allowed: %s.',
                    $type,
                    $index,
                    implode(', ', array_keys(self::KNOWN_STEPS))
                ));
            }

            $risk = strtolower(trim((string) ($step['risk'] ?? 'low')));
            if (!in_array($risk, self::RISK_CLASSES, true)) {
                throw new InvalidArgumentException(sprintf(
                    'Unknown risk class "%s" at step %d. Allowed: %s.',
                    $risk,
                    $index,
                    implode(', ', self::RISK_CLASSES)
                ));
            }

            if (in_array($risk, self::HIGH_IMPACT, true)) {
                $requiresApproval = true;
            }

            // 'fail' is a singleton trigger; other types must be distinct so the
            // engine's index+type idempotency key never collapses two steps.
            if ($type !== 'fail') {
                if (isset($seenTypes[$type])) {
                    throw new InvalidArgumentException(sprintf(
                        'Duplicate step type "%s" at step %d; step types must be distinct within a workflow.',
                        $type,
                        $index
                    ));
                }
                $seenTypes[$type] = true;
            }

            $normalised[] = ['type' => $type, 'risk' => $risk];
        }

        return new WorkflowDefinition($this->workflowId, $normalised, $requiresApproval);
    }
}
