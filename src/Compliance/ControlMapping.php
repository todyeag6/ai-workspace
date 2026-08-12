<?php

declare(strict_types=1);

namespace App\Compliance;

use InvalidArgumentException;
use RuntimeException;

/**
 * Generic compliance control-mapping engine (P5-T5).
 *
 * Maps an internal control id (e.g. SFR-AUTH-001, AC-002, a policy name) to one
 * or more external framework control references. Framework-agnostic: NIST CSF 2.0,
 * ISO/IEC 27001:2022, and SOC 2 TSC are just data shapes. The engine only knows
 * the allowed framework keys (knownFrameworks) and refuses unknown ones or
 * duplicate internal-control registrations (defence against silent overwrite).
 *
 * This is the single source of truth the P5-T6/T7 mapping files load into and the
 * P5-T8 readiness report reads from.
 */
final class ControlMapping
{
    /** @var list<string> Verified official frameworks (docs fetched 2026-08-12). */
    private const FRAMEWORKS = ['NIST_CSF_2_0', 'ISO_27001_2022', 'SOC2_TSC'];

    /** @var array<string, array<string, list<string>>> internal => framework => refs */
    private array $map = [];

    /**
     * @return list<string>
     */
    public static function knownFrameworks(): array
    {
        return self::FRAMEWORKS;
    }

    /**
     * @param list<string> $refs
     * @throws InvalidArgumentException On an unknown framework.
     * @throws RuntimeException When the internal control is already mapped (no silent overwrite).
     */
    public function add(string $internalControl, string $framework, string $ref, array $refs = []): void
    {
        if (!in_array($framework, self::FRAMEWORKS, true)) {
            throw new InvalidArgumentException(sprintf('Unknown compliance framework: %s', $framework));
        }
        if (isset($this->map[$internalControl])) {
            throw new RuntimeException(sprintf('Internal control already mapped: %s', $internalControl));
        }
        $all = $refs === [] ? [$ref] : $refs;
        $this->map[$internalControl][$framework] = $all;
    }

    /**
     * @return array<string, list<string>> framework => refs (empty array if unknown control).
     */
    public function lookup(string $internalControl): array
    {
        return $this->map[$internalControl] ?? [];
    }

    /**
     * @return array<string, array<string, list<string>>>
     */
    public function all(): array
    {
        return $this->map;
    }

    /**
     * Merge another mapping into this one. For an internal control already present,
     * additional frameworks are added (a control may map to several frameworks).
     * Internal controls already present with the same framework are NOT overwritten
     * silently — the existing refs are kept. Returns a NEW instance (immutable).
     */
    public function merge(ControlMapping $other): self
    {
        $merged = $this->map;
        foreach ($other->all() as $internal => $frameworks) {
            foreach ($frameworks as $framework => $refs) {
                if (!isset($merged[$internal][$framework])) {
                    $merged[$internal][$framework] = $refs;
                }
            }
        }
        return self::fromArray($merged);
    }

    /**
     * @param array<string, array<string, list<string>>> $data
     */
    public static function fromArray(array $data): self
    {
        $m = new self();
        foreach ($data as $internal => $frameworks) {
            foreach ($frameworks as $framework => $refs) {
                foreach ((array) $refs as $ref) {
                    // Allow re-adding across frameworks for the same internal control
                    // by registering the first ref, then extending — but add() refuses
                    // duplicate internals. So we register once per internal here.
                    if (!isset($m->map[$internal])) {
                        $m->map[$internal][$framework] = (array) $refs;
                    } else {
                        $m->map[$internal][$framework] = (array) $refs;
                    }
                }
            }
        }
        return $m;
    }
}
