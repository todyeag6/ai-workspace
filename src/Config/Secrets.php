<?php

declare(strict_types=1);

namespace App\Config;

/**
 * Reads configuration secrets from an environment map, failing closed.
 *
 * FR-CONF-001: no secret is ever committed to source; every value arrives
 * through the environment. FR-CONF-002: a required value that is missing,
 * empty or false stops the boot instead of degrading to an empty string.
 *
 * "Absent" deliberately covers three shapes:
 *   - the key is not in the map at all,
 *   - the value is '' (an env var declared but left blank),
 *   - the value is false (what getenv() returns for an unset variable).
 */
final class Secrets
{
    /**
     * @param array<string, mixed> $env Environment map, typically getenv() or $_ENV.
     */
    public function __construct(private array $env)
    {
    }

    /**
     * Returns the value for $key, or throws when it is absent or blank.
     *
     * @throws MissingSecretException When the key resolves to no usable value.
     */
    public function require(string $key): string
    {
        $value = $this->env[$key] ?? '';

        if ($value === '' || $value === false || !is_scalar($value)) {
            // The key name is safe to surface; the value never is.
            throw new MissingSecretException(sprintf('Missing required secret: %s', $key));
        }

        return (string) $value;
    }

    /**
     * Asserts that every key in $keys resolves to a usable value.
     *
     * Call this once at startup so a misconfigured deployment refuses to
     * serve rather than running with half its credentials blank.
     *
     * @param list<string>              $keys Required key names.
     * @param array<string, mixed>|null $env  Environment map; defaults to getenv().
     *
     * @throws MissingSecretException On the first key that is absent or blank.
     */
    public static function validateRequired(array $keys, ?array $env = null): void
    {
        $env ??= getenv();
        $secrets = new self($env);

        foreach ($keys as $key) {
            $secrets->require($key);
        }
    }
}
