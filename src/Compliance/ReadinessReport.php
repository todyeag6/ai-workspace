<?php

/**
 * Compliance readiness report (P5-T8).
 *
 * Aggregates the NIST CSF 2.0 / ISO 27001:2022 / SOC 2 TSC mappings (loaded into
 * a ControlMapping) into a coverage view. Two questions only:
 *   - coveredFrameworks(): which frameworks have at least one mapping
 *   - unmappedControls(): which MANDATORY internal controls are missing from one
 *     or more frameworks (flagged, never silently omitted — fail-visible so a
 *     partial mapping cannot be reported as "compliant").
 *
 * The mandatory set is the platform's shipped controls (SFR/AC/SEC). The owner may
 * pass a different mandatory list when the control baseline changes.
 */

declare(strict_types=1);

namespace App\Compliance;

final class ReadinessReport
{
    /** @var list<string> Shipped mandatory internal controls (P0-P4 baseline). */
    private const MANDATORY = [
        'SFR-AUTH-001', 'SFR-SELF-001', 'SFR-SELF-003',
        'AC-001', 'AC-002', 'AC-006', 'SEC-005',
    ];

    /**
     * @param list<string> $mandatory
     */
    public function __construct(
        private readonly ControlMapping $mapping,
        private readonly array $mandatory = self::MANDATORY,
    ) {
    }

    /**
     * @return list<string> Framework keys that have at least one mapping.
     */
    public function coveredFrameworks(): array
    {
        $covered = [];
        foreach ($this->mapping->all() as $frameworks) {
            foreach (array_keys($frameworks) as $fw) {
                if (!in_array($fw, $covered, true)) {
                    $covered[] = $fw;
                }
            }
        }
        return $covered;
    }

    /**
     * @return array<string, list<string>> control => frameworks it is missing.
     *   Only contains controls that have at least one missing framework; a fully
     *   mapped control is omitted (so an empty result == full coverage).
     */
    public function unmappedControls(): array
    {
        $known = ControlMapping::knownFrameworks();
        $gaps = [];
        foreach ($this->mandatory as $ctrl) {
            $present = array_keys($this->mapping->lookup($ctrl));
            $missing = array_values(array_diff($known, $present));
            if ($missing !== []) {
                $gaps[$ctrl] = $missing;
            }
        }
        return $gaps;
    }

    /**
     * @return array<string, array<string, list<string>>> the full merged mapping.
     */
    public function mapping(): array
    {
        return $this->mapping->all();
    }
}
