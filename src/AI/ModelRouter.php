<?php

declare(strict_types=1);

namespace App\AI;

use InvalidArgumentException;

/**
 * Decides which runtime serves a call: the on-premises model, a hosted
 * provider, or neither (FR-AI-001).
 *
 * THE RULE, in full, because a routing policy nobody can recite is one nobody
 * can audit:
 *
 *   1. Local wins whenever it is reachable AND the latency budget clears the
 *      floor for the quality being asked for. Local-first is the default
 *      because it keeps client data on premises and costs nothing per token.
 *   2. Otherwise the cloud, when one is configured and available, AND its cost
 *      clears any ceiling the caller set. Cost is a tie-breaker on top of the
 *      latency/quality rule, not a replacement for it: a call that cannot meet
 *      the latency floor is not rescued by being cheap.
 *   3. Otherwise local anyway, if it is reachable - a budget that is merely
 *      tight is a better bet than a queued human when there is no alternative.
 *   4. Otherwise 'review': the call goes to a person.
 *
 * COST (added for P2-T2): when a $costCeilingCents is supplied, a runtime whose
 * estimated cost exceeds it is treated as unavailable for that call. Local is
 * treated as zero-cost when no estimate is given (it has no per-token price),
 * so the local-first default is preserved; the ceiling matters most for the
 * cloud path, where a call the budget cannot pay for is routed to review
 * rather than silently over-spending. A null ceiling means "cost is not
 * considered", keeping the pre-P2-T2 behaviour for every existing caller.
 *
 * WHY 'review' AND NOT AN EXCEPTION: "no model is available" is an operational
 * state, not a programming error. A throw here would surface to a user as a
 * 500 in the middle of a workflow; a disposition lets the workflow park the
 * item where a human will see it, which is what actually has to happen either
 * way. The disposition string matches AIResult::DISPOSITION_REVIEW so the two
 * ends of the pipeline speak the same word.
 *
 * WHY THE FLOOR MOVES WITH qualityNeed: a draft answer from a local 8B model
 * lands in well under a second; a careful one takes several. One global
 * threshold would either send every quality call to the cloud or promise the
 * caller a local answer it cannot deliver inside the budget.
 *
 * Availability is INJECTED, not probed here: a router that pings runtimes
 * would be untestable without a network and would add a health check to the
 * latency of every call. Probing belongs to whatever already knows the health
 * of the fleet.
 *
 * © AI WebScapes 2026
 */
final class ModelRouter
{
    public const LOCAL = 'local';
    public const CLOUD = 'cloud';
    public const REVIEW = 'review';

    /**
     * Milliseconds the local runtime realistically needs, per quality need.
     * Deliberately coarse: these are routing thresholds, not SLAs.
     *
     * @var array<string, int>
     */
    private const LOCAL_FLOOR_MS = [
        'draft' => 750,
        'standard' => 1500,
        'quality' => 4000,
    ];

    public function __construct(
        private readonly bool $localReachable,
        private readonly bool $cloudAvailable
    ) {
    }

    /**
     * @param  int         $budgetMs    Wall-clock milliseconds the caller can wait.
     * @param  string      $qualityNeed draft | standard | quality.
     * @param  int|null    $costCeilingCents  Optional per-call spend ceiling. A
     *                                        runtime estimated above it is treated
     *                                        as unavailable. Null = cost ignored
     *                                        (pre-P2-T2 behaviour).
     * @param  int|null    $localCostCents    Estimated local cost for the call.
     *                                        Defaults to 0 (local has no token
     *                                        price) when null.
     * @param  int|null    $cloudCostCents    Estimated cloud cost for the call.
     * @return string One of self::LOCAL, self::CLOUD, self::REVIEW.
     *
     * @throws InvalidArgumentException On a budget of zero or less, or a
     *                                  quality need this router has no floor
     *                                  for - guessing at either would route
     *                                  silently and wrongly.
     */
    public function select(
        int $budgetMs,
        string $qualityNeed,
        ?int $costCeilingCents = null,
        ?int $localCostCents = null,
        ?int $cloudCostCents = null
    ): string {
        if ($budgetMs <= 0) {
            throw new InvalidArgumentException(sprintf(
                'A latency budget must be greater than zero milliseconds, got %d.',
                $budgetMs
            ));
        }

        $floorMs = self::LOCAL_FLOOR_MS[$qualityNeed] ?? null;

        if ($floorMs === null) {
            throw new InvalidArgumentException(sprintf(
                'Unknown quality need "%s". Allowed: %s.',
                $qualityNeed,
                implode(', ', array_keys(self::LOCAL_FLOOR_MS))
            ));
        }

        $localCost = $localCostCents ?? 0;
        $localWithinBudget = $this->localReachable && $budgetMs >= $floorMs;
        $localCostOk = $costCeilingCents === null || $localCost <= $costCeilingCents;
        $cloudCostOk = $costCeilingCents === null
            || ($cloudCostCents !== null && $cloudCostCents <= $costCeilingCents);

        // Rule 1 (+cost): local-first when it can serve both the latency floor
        // and the cost ceiling. Local is the default because it is free and
        // on-premises.
        if ($localWithinBudget && $localCostOk) {
            return self::LOCAL;
        }

        // Rule 2 (+cost): cloud when local cannot serve, the cloud is up, and
        // the cloud clears the ceiling (or no ceiling was set).
        if ($this->cloudAvailable && $cloudCostOk) {
            return self::CLOUD;
        }

        // Rule 3 (+cost): local anyway if reachable and within the cost ceiling
        // - a tight budget beats a human, provided the call can be paid for.
        // When the ceiling is set and local is over it (and cloud was too), we
        // fall through to review rather than spending beyond the budget.
        if ($this->localReachable && $localCostOk) {
            return self::LOCAL;
        }

        // Rule 4: nobody can serve this call within budget and cost; park it
        // for a person.
        return self::REVIEW;
    }
}
