<?php

declare(strict_types=1);

namespace App\AI;

use InvalidArgumentException;

/**
 * Validates a decoded model output against the schema its request declared
 * (FR-AI-003).
 *
 * WHY A HAND-ROLLED VALIDATOR: the schemas here describe one model response -
 * a handful of named fields, scalars, one level or two of nesting. Pulling in
 * a full JSON Schema implementation would add a dependency (and its CVE
 * surface, and its SBOM entry) to check less than this file does, because the
 * property that matters is not "draft 2020-12 conformance", it is "downstream
 * code can index this array without guessing".
 *
 * THE SCHEMA LANGUAGE, in full:
 *
 *   [
 *     'lead_score'         => 'int',        // required scalar
 *     'notes'              => 'string?',    // optional - may be absent
 *     'follow_up_required' => 'bool',
 *     'contact'            => [             // nested object, required
 *         'email' => 'string',
 *         'name'  => 'string?',
 *     ],
 *   ]
 *
 * Types are 'string', 'int', 'float', 'bool' and 'array'; a trailing '?'
 * marks a field that may be absent. A nested array is an object schema and
 * recurses.
 *
 * WHY 'array' EXISTS (added when the manager orchestrator was first driven end
 * to end). TaskDecomposer asks for `['tasks' => 'array']` and ReviewLoop for
 * `['findings' => 'array']` - both need to describe a VARIABLE-LENGTH LIST of
 * values, which the object-schema form cannot express, because an object schema
 * names its keys. Before 'array' existed those two requests were unbuildable:
 * assertSchema() rejected the type name and AIRequest threw at construction, so
 * ManagerOrchestrator::manage() could never have completed a single call. The
 * bug was latent because nothing exercised the path - the first end-to-end
 * invocation surfaced it.
 *
 * 'array' means a JSON LIST (array_is_list), not "any array". A list is what
 * `[...]` decodes to; an object decodes to a string-keyed array and is the
 * nested-schema case, not this one. Keeping them distinct means a model that
 * answers `{"tasks": {"a": 1}}` where a list was required is caught here rather
 * than blowing up in the caller's foreach.
 *
 * NULL IS NOT A VALUE HERE: 'string?' means "the key may be absent", not "the
 * key may be null". An explicit null from a model is almost always a failed
 * extraction rather than a considered answer, and letting it through as a
 * valid string field is precisely the class of bug FR-AI-003 exists to stop.
 *
 * © AI WebScapes 2026
 */
final class SchemaValidator
{
    /**
     * @var list<string>
     */
    private const SCALAR_TYPES = ['string', 'int', 'float', 'bool'];

    /**
     * Types that describe a JSON list rather than a single value. Kept separate
     * from SCALAR_TYPES because the error message a caller sees should name the
     * full set of what is allowed, and because matches() treats them
     * differently - a scalar is one value, an array is many.
     *
     * @var list<string>
     */
    private const LIST_TYPES = ['array'];

    /**
     * @param array<array-key, mixed> $data   Decoded model output.
     * @param array<array-key, mixed> $schema As described in the class docblock.
     */
    public function validate(array $data, array $schema): bool
    {
        return $this->errors($data, $schema) === [];
    }

    /**
     * Every reason $data fails $schema, so a review queue entry can say what
     * was wrong instead of just "invalid". Empty list means valid.
     *
     * @param  array<array-key, mixed> $data
     * @param  array<array-key, mixed> $schema
     * @param  string                  $path Dotted prefix used in messages while recursing.
     * @return list<string>
     */
    public function errors(array $data, array $schema, string $path = ''): array
    {
        $errors = [];

        foreach ($schema as $key => $expected) {
            $field = $path === '' ? (string) $key : $path . '.' . $key;
            $present = array_key_exists($key, $data);
            $value = $present ? $data[$key] : null;

            if (is_array($expected)) {
                if (!$present) {
                    $errors[] = sprintf('%s: missing required object', $field);

                    continue;
                }

                if (!is_array($value)) {
                    $errors[] = sprintf('%s: expected an object, got %s', $field, get_debug_type($value));

                    continue;
                }

                foreach ($this->errors($value, $expected, $field) as $nested) {
                    $errors[] = $nested;
                }

                continue;
            }

            if (!is_string($expected)) {
                // Unreachable through AIRequest, which calls assertSchema().
                $errors[] = sprintf('%s: schema entry is not a type name', $field);

                continue;
            }

            $optional = str_ends_with($expected, '?');
            $type = $optional ? substr($expected, 0, -1) : $expected;

            if (!$present) {
                if (!$optional) {
                    $errors[] = sprintf('%s: missing required %s', $field, $type);
                }

                continue;
            }

            if (!$this->matches($value, $type)) {
                $errors[] = sprintf('%s: expected %s, got %s', $field, $type, get_debug_type($value));
            }
        }

        foreach (array_keys($data) as $key) {
            if (!array_key_exists($key, $schema)) {
                $errors[] = sprintf(
                    '%s: unexpected key not described by the schema',
                    $path === '' ? (string) $key : $path . '.' . $key
                );
            }
        }

        return $errors;
    }

    /**
     * Rejects a malformed schema at CONFIGURATION time.
     *
     * Called from AIRequest's constructor so a typo like 'integer' fails when
     * the request is built, not at 3am when a model output that was actually
     * fine gets sent to review because nothing could ever match it.
     *
     * @param array<array-key, mixed> $schema
     */
    public static function assertSchema(array $schema, string $path = ''): void
    {
        if ($schema === []) {
            throw new InvalidArgumentException(sprintf(
                'The expected output schema%s is empty. FR-AI-002 requires a call to '
                . 'declare the shape it expects back; an empty schema declares nothing.',
                $path === '' ? '' : ' at "' . $path . '"'
            ));
        }

        foreach ($schema as $key => $expected) {
            $field = $path === '' ? (string) $key : $path . '.' . $key;

            if (!is_string($key) || $key === '') {
                throw new InvalidArgumentException(sprintf(
                    'Schema field "%s" must be a non-empty string key.',
                    $field
                ));
            }

            if (is_array($expected)) {
                self::assertSchema($expected, $field);

                continue;
            }

            if (!is_string($expected)) {
                throw new InvalidArgumentException(sprintf(
                    'Schema field "%s" must map to a type name or a nested schema, got %s.',
                    $field,
                    get_debug_type($expected)
                ));
            }

            $type = str_ends_with($expected, '?') ? substr($expected, 0, -1) : $expected;

            if (!in_array($type, self::SCALAR_TYPES, true) && !in_array($type, self::LIST_TYPES, true)) {
                throw new InvalidArgumentException(sprintf(
                    'Schema field "%s" declares unknown type "%s". Allowed: %s (append "?" for optional).',
                    $field,
                    $expected,
                    implode(', ', [...self::SCALAR_TYPES, ...self::LIST_TYPES])
                ));
            }
        }
    }

    /**
     * WHY int SATISFIES float: JSON has one number type, so a model answering
     * 1 for a 'float' field is correct and json_decode simply hands back an
     * int. Rejecting it would fail valid output. The reverse is NOT allowed -
     * 1.5 for an 'int' field is a real mismatch.
     *
     * WHY 'array' REQUIRES array_is_list: a JSON list `[...]` is the thing a
     * caller will foreach over. A JSON object `{...}` also decodes to a PHP
     * array, so is_array() alone would accept `{"tasks": {"a": 1}}` for a field
     * declared as a list and hand the caller a structure it cannot iterate the
     * way it expects. Requiring a list keeps the two shapes distinct.
     */
    private function matches(mixed $value, string $type): bool
    {
        return match ($type) {
            'string' => is_string($value),
            'int' => is_int($value),
            'float' => is_float($value) || is_int($value),
            'bool' => is_bool($value),
            'array' => is_array($value) && array_is_list($value),
            default => false,
        };
    }
}
