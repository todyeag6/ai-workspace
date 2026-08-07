<?php

declare(strict_types=1);

namespace App\Assessment;

use DomainException;

/**
 * BAAF-003 / BAAF-006 — a process is ownerless or lacks mandated safeguards
 * (explicit no-go criteria + safe fallback), so it must not be automated.
 *
 * © AI WebScapes 2026
 */
final class ProcessDefectException extends DomainException
{
}
