<?php

declare(strict_types=1);

namespace App\Tests\AI;

use App\AI\ModelRouter;
use PHPUnit\Framework\TestCase;

/**
 * P2-T2 cost-aware model routing.
 *
 * The latency/quality rules were proven in tests/AI/AdapterTest.php. These
 * tests cover ONLY the new cost dimension and that the pre-existing behaviour
 * is preserved when no ceiling is supplied.
 *
 * © AI WebScapes 2026
 */
final class ModelRouterCostTest extends TestCase
{
    public function test_local_first_when_within_latency_and_cost(): void
    {
        $router = new ModelRouter(localReachable: true, cloudAvailable: true);
        // Local is free (default cost 0) and within latency -> local wins even
        // with a tight cost ceiling.
        self::assertSame(
            ModelRouter::LOCAL,
            $router->select(budgetMs: 8000, qualityNeed: 'standard', costCeilingCents: 1, localCostCents: 0, cloudCostCents: 5)
        );
    }

    public function test_cloud_chosen_when_local_over_cost_ceiling_but_cloud_clears_it(): void
    {
        $router = new ModelRouter(localReachable: true, cloudAvailable: true);
        // Local would cost 50c, ceiling is 10c, cloud is 4c and available.
        self::assertSame(
            ModelRouter::CLOUD,
            $router->select(budgetMs: 8000, qualityNeed: 'standard', costCeilingCents: 10, localCostCents: 50, cloudCostCents: 4)
        );
    }

    public function test_review_when_both_runtimes_exceed_cost_ceiling(): void
    {
        $router = new ModelRouter(localReachable: true, cloudAvailable: true);
        // Neither local (50c) nor cloud (30c) clears a 10c ceiling.
        self::assertSame(
            ModelRouter::REVIEW,
            $router->select(budgetMs: 8000, qualityNeed: 'standard', costCeilingCents: 10, localCostCents: 50, cloudCostCents: 30)
        );
    }

    public function test_cost_ignored_when_no_ceiling_supplied_pre_p2t2_behaviour(): void
    {
        $router = new ModelRouter(localReachable: true, cloudAvailable: true);
        // With no ceiling, local-first still holds regardless of the (ignored)
        // cost estimates. This pins the backward-compatible path.
        self::assertSame(
            ModelRouter::LOCAL,
            $router->select(budgetMs: 8000, qualityNeed: 'standard')
        );
        self::assertSame(
            ModelRouter::CLOUD,
            (new ModelRouter(localReachable: false, cloudAvailable: true))
                ->select(budgetMs: 8000, qualityNeed: 'standard')
        );
    }

    public function test_latency_floor_still_wins_over_cost_cheapness(): void
    {
        $router = new ModelRouter(localReachable: true, cloudAvailable: true);
        // Local cannot meet the quality latency floor (tight budget), so even
        // though local is free it is not chosen; cloud clears floor + ceiling.
        self::assertSame(
            ModelRouter::CLOUD,
            $router->select(budgetMs: 200, qualityNeed: 'quality', costCeilingCents: 100, localCostCents: 0, cloudCostCents: 4)
        );
    }
}
