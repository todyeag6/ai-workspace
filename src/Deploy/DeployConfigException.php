<?php

declare(strict_types=1);

namespace App\Deploy;

use RuntimeException;

/**
 * Thrown when a client deploy config fails validation (P4-T3, fail-closed).
 */
final class DeployConfigException extends RuntimeException
{
}
