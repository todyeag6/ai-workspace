<?php

declare(strict_types=1);

namespace App\Tests\ManagedOps;

use App\ManagedOps\AgentOwnership;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * P2-T4 ownership roster - the value object's invariants.
 *
 * The regression value is in the refusal tests: an unknown role is refused
 * (a typo'd owner lookup must fail loud, not read "no owner"), and the
 * canonical role list matches the baseline's mandated accountable parties
 * (BR-9.1 update/backup owner, BR-11.1 five roles).
 *
 * © AI WebScapes 2026
 */
final class AgentOwnershipTest extends TestCase
{
    /**
     * @param array<string, string> $roles
     */
    private function ownership(array $roles = []): AgentOwnership
    {
        $defaults = array_fill_keys(AgentOwnership::roleNames(), 'x');
        return new AgentOwnership(1, 1, array_merge($defaults, $roles), 'client owns infra', 'alice');
    }

    public function test_role_names_match_baseline(): void
    {
        self::assertSame(
            [
                'business_owner',
                'technical_owner',
                'data_owner',
                'security_owner',
                'acceptance_authority',
                'update_owner',
                'backup_owner',
            ],
            AgentOwnership::roleNames()
        );
    }

    public function test_reads_a_known_role(): void
    {
        $o = $this->ownership(['business_owner' => 'bob']);
        self::assertSame('bob', $o->ownerOf('business_owner'));
    }

    public function test_refuses_unknown_role_lookup(): void
    {
        $o = $this->ownership();
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown ownership role "wizard"');
        $o->ownerOf('wizard');
    }

    public function test_accepts_empty_support_boundary(): void
    {
        $o = new AgentOwnership(1, 1, array_fill_keys(AgentOwnership::roleNames(), 'x'), '', 'alice');
        self::assertSame('', $o->supportBoundary);
    }
}
