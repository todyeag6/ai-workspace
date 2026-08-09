<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Data\TenantRepository;

/**
 * The tenant-scoped safety trail for a scan (SFR-SAFE-002, SBR-3.5).
 *
 * WHY A SEPARATE REPOSITORY AND NOT A METHOD ON ScanRepository. App\Data\
 * TenantRepository binds one subclass to one table - that is what makes the
 * scope predicate impossible to omit. Writing scan_events from the
 * security_scans repository would mean reaching around that guarantee, so the
 * second table gets a second scoped repository, exactly as
 * AuthorizationRepository composes ScanTargetRepository.
 *
 * WHY EVERY REFUSAL WRITES HERE FIRST. The P3 exit-gate tests do not ask
 * whether a scan stopped, they ask whether the stop is EVIDENCED. SafetyMonitor
 * therefore records the event before it returns the verdict, so no code path
 * can refuse silently.
 *
 * © AI WebScapes 2026
 */
final class ScanEventRepository extends TenantRepository
{
    /** scan_events.detail is TEXT; a runaway detail is truncated, not refused. */
    private const DETAIL_MAX = 2000;

    protected function table(): string
    {
        return 'scan_events';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'scan_id',
            'event_type',
            'detail',
            'occurred_at',
        ];
    }

    /**
     * Records one safety event against a scan.
     *
     * The caller is responsible for having established that $scanId is visible
     * in this tenant - ScanRepository::recordEvent() does exactly that before
     * delegating here, so an event can never be attached to another tenant's
     * scan.
     */
    public function add(int $scanId, string $eventType, ?string $detail = null): int
    {
        return (int) $this->insertScoped([
            'scan_id' => $scanId,
            'event_type' => $eventType,
            'detail' => $detail === null ? null : mb_substr($detail, 0, self::DETAIL_MAX),
        ]);
    }

    /**
     * The recorded trail for one scan, oldest first - the sanctioned read for
     * a report or an operator view.
     *
     * @return list<array<string, scalar|null>>
     */
    public function forScan(int $scanId): array
    {
        return $this->selectScoped('scan_id = :scan_id ORDER BY id ASC', ['scan_id' => $scanId]);
    }

    /**
     * How many events of one type this scan has recorded.
     */
    public function countOfType(int $scanId, string $eventType): int
    {
        $rows = $this->selectScoped(
            'scan_id = :scan_id AND event_type = :event_type',
            ['scan_id' => $scanId, 'event_type' => $eventType]
        );

        return count($rows);
    }
}
