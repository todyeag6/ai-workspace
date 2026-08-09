<?php

declare(strict_types=1);

namespace App\VerticalOffering;

use RuntimeException;

/**
 * Raised when a vertical template file cannot be loaded or parsed (P2-T5).
 *
 * Distinct from InvalidArgumentException (which is the "the template content is
 * structurally invalid" case) so a caller can tell "the file is missing" from
 * "the file parsed but failed validation".
 *
 * © AI WebScapes 2026
 */
final class VertalTemplateLoadFailure extends RuntimeException
{
}
