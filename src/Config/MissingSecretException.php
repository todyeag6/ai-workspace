<?php

declare(strict_types=1);

namespace App\Config;

use RuntimeException;

/**
 * Thrown when a required configuration secret is absent or blank.
 *
 * FR-CONF-002 / SEC-006: the platform fails closed. Booting with an empty
 * credential is treated as a fatal misconfiguration, never as a default.
 *
 * PSR-1 requires one class per file, so this lives beside Secrets rather
 * than inside it.
 */
final class MissingSecretException extends RuntimeException
{
}
