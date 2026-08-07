<?php

declare(strict_types=1);

namespace App\Leads;

/**
 * Who owns a lead, and on whose authority (LFR-ROUTE-001).
 *
 * `source` is carried alongside `owner` because "the rule decided" and "the
 * model suggested" are different facts with different review consequences, and
 * a decision that records only the outcome cannot be audited afterwards. A
 * routing dispute is settled by reading this field.
 *
 * The class holds no logic: LeadService::route() is where a business rule
 * OVERRIDES the model, and centralising that decision is the point.
 *
 * © AI WebScapes 2026
 */
final class RouteDecision
{
    /** A deterministic business rule chose the owner. The model was ignored. */
    public const SOURCE_RULE = 'rule';

    /** No rule applied, so the model's suggestion was accepted. */
    public const SOURCE_AI = 'ai';

    /** Neither a rule nor the model named a usable owner. */
    public const SOURCE_DEFAULT = 'default';

    public function __construct(
        public readonly string $owner,
        public readonly string $source
    ) {
    }

    /**
     * @return array{owner: string, source: string}
     */
    public function toArray(): array
    {
        return ['owner' => $this->owner, 'source' => $this->source];
    }
}
