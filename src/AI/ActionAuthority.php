<?php

declare(strict_types=1);

namespace App\AI;

/**
 * The one place that decides whether a model output may authorise an action
 * (FR-AI-006).
 *
 * WHY THIS IS NOT A METHOD ON AIGateway: AC-003 requires the gateway to hold
 * no effectful collaborator, and "authorise this transaction" is the single
 * most effectful thing in the system. Keeping the authoriser separate means
 * the gateway still cannot act on its own output - it hands a result back and
 * something else, holding this class, decides. Merging them would put "is the
 * output valid?" and "may we act on it?" in one object where the second could
 * no longer be reasoned about, tested or refused independently of the first.
 *
 * THE REFUSAL IS CONTENT-BLIND ON PURPOSE. authorizeTransaction() never reads
 * $modelOutput. A rule of the form "refuse unless the model says it is safe"
 * is exactly the excessive agency SEC-010 is about: the attacker controls the
 * text, so they control the exemption. Risk class is set by the CALLER - the
 * workflow definition, not the model - which is why it, and not the output,
 * decides.
 *
 * 'low' and 'medium' return normally. That is not "the AI approved it": it
 * means this class has no objection and the action continues to whatever
 * policy or human step the workflow defines. Refusing everything would make
 * the method a synonym for "throw" and it would be routed around within a
 * week.
 *
 * © AI WebScapes 2026
 */
final class ActionAuthority
{
    /**
     * Impacts no autonomous system may sign off: money movement, destructive
     * changes, anything with a legal or contractual footprint.
     *
     * @var list<string>
     */
    private const HIGH_IMPACT = ['high', 'critical'];

    /**
     * Impacts that may proceed to the workflow's own policy or reviewer.
     *
     * @var list<string>
     */
    private const PROCEEDABLE = ['low', 'medium'];

    /**
     * Refuses to let AI-generated content authorise a high-impact transaction.
     *
     * @param mixed  $modelOutput Deliberately unread; present so the call site
     *                            documents WHAT is being authorised and so the
     *                            refusal can name its type for the audit trail.
     * @param string $riskClass   low | medium | high | critical, set by the
     *                            workflow that owns the action.
     *
     * @throws AutonomousActionRejected When the class is high, critical, or
     *                                  not recognised at all.
     */
    public function authorizeTransaction(mixed $modelOutput, string $riskClass): void
    {
        $normalised = strtolower(trim($riskClass));

        if (in_array($normalised, self::HIGH_IMPACT, true)) {
            throw AutonomousActionRejected::highImpact($normalised, get_debug_type($modelOutput));
        }

        if (!in_array($normalised, self::PROCEEDABLE, true)) {
            // Fails CLOSED: an unknown class is an unreviewed one, and the
            // alternative default silently authorises every typo.
            throw AutonomousActionRejected::unknownRiskClass($riskClass);
        }
    }
}
