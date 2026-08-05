<?php

declare(strict_types=1);

namespace App\Infra;

use InvalidArgumentException;

/**
 * Long-option parsing for the operational scripts in scripts/.
 *
 * Supports "--name=value" and bare "--flag". Deliberately minimal: the point
 * is not to reimplement getopt but to make "an option was not supplied"
 * a loud, typed failure rather than a silent default.
 *
 * That distinction is the whole prod-safety story for these scripts. None of
 * them may fall back to an ambient DB_DSN, because an operator running
 * backup.php or restore.php in the wrong shell would then quietly act on the
 * production database. requireValue() throws instead.
 */
final class CliOptions
{
    /**
     * @param array<string, string|true> $values value for --k=v, true for --flag
     */
    private function __construct(private readonly array $values)
    {
    }

    /**
     * @param list<string> $arguments argv WITHOUT the script name
     */
    public static function fromArgv(array $arguments): self
    {
        $values = [];

        foreach ($arguments as $argument) {
            if (!str_starts_with($argument, '--')) {
                throw new InvalidArgumentException(
                    sprintf('Unexpected argument "%s": only --long options are accepted.', $argument)
                );
            }

            $argument = substr($argument, 2);
            $separator = strpos($argument, '=');

            if ($separator === false) {
                $values[$argument] = true;
                continue;
            }

            $values[substr($argument, 0, $separator)] = substr($argument, $separator + 1);
        }

        return new self($values);
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->values);
    }

    /**
     * The value of --name, or null when it was not supplied with one.
     */
    public function value(string $name): ?string
    {
        $value = $this->values[$name] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * The value of --name, falling back to an environment variable and then to
     * a literal default.
     *
     * Used for credentials only, never for the DSN: getting the username
     * wrong produces an access-denied error, whereas getting the DSN wrong
     * silently operates on the wrong database.
     */
    public function valueOrEnv(string $name, string $environmentVariable, string $fallback): string
    {
        $value = $this->value($name);
        if ($value !== null) {
            return $value;
        }

        $fromEnvironment = getenv($environmentVariable);

        return is_string($fromEnvironment) && $fromEnvironment !== '' ? $fromEnvironment : $fallback;
    }

    /**
     * @throws InvalidArgumentException when --name is absent or has no value
     */
    public function requireValue(string $name): string
    {
        $value = $this->value($name);
        if ($value === null) {
            throw new InvalidArgumentException(
                sprintf('Missing required option --%s=<value>.', $name)
            );
        }

        return $value;
    }
}
