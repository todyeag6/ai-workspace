<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use RuntimeException;

/**
 * Thrown when a report would mix rows belonging to more than one tenant.
 *
 * THE ACCEPTANCE TEST THIS ENFORCES, VERBATIM
 * --------------------------------------------
 * FRD section 7, "Cross tenant" row: "No finding/evidence/report access across
 * tenant."
 *
 * WHY A REPORT NEEDS ITS OWN CHECK WHEN THE REPOSITORIES ARE ALREADY SCOPED
 * -------------------------------------------------------------------------
 * Every repository in this module extends App\Data\TenantRepository, so rows
 * arrive scoped (AC-001). But the report BUILDER takes already-hydrated value
 * objects as arguments — it has no PDO and runs no query — which means the
 * scope guarantee lives entirely in the caller's discipline at that seam. A
 * caller that hydrated two tenants' findings and passed both lists would
 * produce a cross-tenant report with every underlying query correctly scoped.
 *
 * So the builder re-checks the one thing it can still see: every value object
 * carries its own tenantId(), and they must all match the tenant the report is
 * for. Cheap, total, and it fails closed. Defence in depth at the exact seam
 * where the database's guarantee stops applying.
 *
 * Carries both tenant ids so the refusal names the boundary that was crossed.
 *
 * © AI WebScapes 2026
 */
final class CrossTenantReportRefused extends RuntimeException
{
    public function __construct(
        private readonly int $reportTenantId,
        private readonly int $foreignTenantId,
        private readonly string $itemType,
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    /** The tenant the report is being built for. */
    public function reportTenantId(): int
    {
        return $this->reportTenantId;
    }

    /** The tenant the offending row actually belonged to. */
    public function foreignTenantId(): int
    {
        return $this->foreignTenantId;
    }

    /** What kind of row it was (finding, remediation, retest, acceptance). */
    public function itemType(): string
    {
        return $this->itemType;
    }
}
