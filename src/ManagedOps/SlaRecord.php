<?php

declare(strict_types=1);

namespace App\ManagedOps;

use InvalidArgumentException;

/**
 * A single SLA measurement (P2-T4 managed-ops substrate).
 *
 * Grounded in BRD Table 4 "Security" KPI category: patch SLA, incident
 * frequency, backup restore test success. An SLA is one of those types with a
 * TARGET and an OBSERVED duration (hours); it is BREACHED when the observed
 * duration exceeds the target. The breach flag is computed HERE, at
 * construction, so the immutable row the repository writes can carry it
 * (queryable without re-deriving) and it can never drift from the numbers.
 *
 * Plain value object, no IO - unit-testable without MySQL, like the ownership
 * and workflow-definition objects.
 *
 * © AI WebScapes 2026
 */
final class SlaRecord
{
    /** @var list<string> The BRD Table 4 security SLA types this tracks. */
    private const TYPES = ['patch', 'incident_response', 'backup_restore_test'];

    public function __construct(
        public readonly string $slaType,
        public readonly float $targetHours,
        public readonly float $observedHours,
        public readonly ?string $measuredAt = null
    ) {
        if (!in_array($slaType, self::TYPES, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown SLA type "%s". Allowed: %s.',
                $slaType,
                implode(', ', self::TYPES)
            ));
        }
        if ($targetHours < 0 || $observedHours < 0) {
            throw new InvalidArgumentException('SLA hours must be non-negative.');
        }
    }

    /**
     * Breach = observed longer than the target. Equality is not a breach:
     * meeting the target exactly is a pass.
     */
    public function isBreached(): bool
    {
        return $this->observedHours > $this->targetHours;
    }

    /**
     * The breach flag the (immutable) repository row stores - 1 or 0.
     */
    public function breachedFlag(): int
    {
        return $this->isBreached() ? 1 : 0;
    }

    /**
     * @return list<string>
     */
    public static function types(): array
    {
        return self::TYPES;
    }
}
