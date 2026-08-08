<?php

declare(strict_types=1);

namespace App\ManagedOps;

use InvalidArgumentException;

/**
 * The support model for an engagement (P2-T4 managed-ops substrate).
 *
 * Pure value object - no table of its own. BR-9.1 [Must] requires every
 * solution to state its "support boundary"; BR-12.6 [Must] requires incident
 * contacts, vulnerability intake and patching responsibility. This object is
 * the in-code expression of that: a support TIER (which dictates the SLA
 * ceilings the SlaRecord rows are measured against), the named escalation
 * CONTACTS, and the boundary text that says what the client owns vs what the
 * managed service owns. It is built by a controller from the engagement record
 * and handed to the reporting/assembler layer; it performs no IO.
 *
 * WHY A VALUE OBJECT AND NOT A ROW: the support model is configuration that
 * travels with the engagement, not an event to be appended. Keeping it a VO
 * (like ReportData) means it is testable and composable without a write path,
 * and the actual support contract text still lives in the engagement/ownership
 * record where it belongs.
 *
 * © AI WebScapes 2026
 */
final class SupportModel
{
    /** @var list<string> Supported tiers, in ascending commitment. */
    private const TIERS = ['basic', 'standard', 'premium', 'mission_critical'];

    /**
     * @param string $tier One of TIERS.
     * @param list<array{role: string, channel: string, target: string}> $contacts
     *        Named escalation contacts (BR-12.6): role, channel, response target.
     * @param string $boundary The BR-9.1 support boundary statement.
     */
    public function __construct(
        public readonly string $tier,
        public readonly array $contacts,
        public readonly string $boundary
    ) {
        if (!in_array($tier, self::TIERS, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown support tier "%s". Allowed: %s.',
                $tier,
                implode(', ', self::TIERS)
            ));
        }
    }

    public function tier(): string
    {
        return $this->tier;
    }

    /**
     * @return list<array{role: string, channel: string, target: string}>
     */
    public function contacts(): array
    {
        return $this->contacts;
    }

    public function boundary(): string
    {
        return $this->boundary;
    }

    /**
     * @return list<string>
     */
    public static function tiers(): array
    {
        return self::TIERS;
    }
}
