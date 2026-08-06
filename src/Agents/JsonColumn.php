<?php

declare(strict_types=1);

namespace App\Agents;

use InvalidArgumentException;

/**
 * Encode/decode for the two JSON-shaped text columns in the agent registry
 * (`agents.data_classes`, `agent_versions.allowed_tools` and
 * `agent_versions.model_config`).
 *
 * WHY TEXT AND NOT MySQL's JSON TYPE: PDO hands a JSON column back as a string
 * anyway, so the type buys no PHP-side safety here, while it does forbid a
 * plain column DEFAULT - and the schema wants `DEFAULT '[]'` so that a row
 * inserted by anything other than this code still reads back as "no tools"
 * rather than NULL. Least-privilege defaults beat column-type purity.
 *
 * WHY THE DECODERS DISCARD WHAT THEY CANNOT TYPE: json_decode() returns mixed,
 * and at PHPStan level 8 that mixed has to be narrowed exactly once, in one
 * place, or every caller narrows it slightly differently. A tool name that is
 * not a string is not a tool name - dropping it is both the safe reading (a
 * malformed allow-list grants nothing) and the checkable one.
 *
 * © AI WebScapes 2026
 */
final class JsonColumn
{
    /**
     * @param list<string> $values
     */
    public static function encodeList(array $values): string
    {
        return self::encode($values);
    }

    /**
     * @param array<string, scalar|null> $values
     */
    public static function encodeMap(array $values): string
    {
        return $values === [] ? '{}' : self::encode($values);
    }

    /**
     * @return list<string>
     */
    public static function decodeList(string $json): array
    {
        $decoded = json_decode($json, true);
        if (!is_array($decoded)) {
            return [];
        }

        $values = [];
        foreach ($decoded as $value) {
            if (is_string($value)) {
                $values[] = $value;
            }
        }

        return $values;
    }

    /**
     * @return array<string, scalar|null>
     */
    public static function decodeMap(string $json): array
    {
        $decoded = json_decode($json, true);
        if (!is_array($decoded)) {
            return [];
        }

        $values = [];
        foreach ($decoded as $key => $value) {
            if (!is_string($key)) {
                continue;
            }

            if ($value !== null && !is_scalar($value)) {
                continue;
            }

            $values[$key] = $value;
        }

        return $values;
    }

    /**
     * @param array<array-key, scalar|null> $values
     */
    private static function encode(array $values): string
    {
        $json = json_encode($values);
        if ($json === false) {
            // Reachable only for invalid UTF-8, which is a defect in the
            // caller's data rather than something to persist half of.
            throw new InvalidArgumentException(sprintf(
                'Cannot store the value as JSON: %s.',
                json_last_error_msg()
            ));
        }

        return $json;
    }
}
