<?php

declare(strict_types=1);

namespace App\Tests\AI;

use App\AI\SchemaValidator;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The schema language (FR-AI-003).
 *
 * This file did not exist before: SchemaValidator had no direct test, and its
 * behaviour was only exercised incidentally through AIGatewayTest. That gap is
 * exactly why a real defect survived in it - TaskDecomposer and ReviewLoop both
 * declared `'array'`, a type the validator refused, so every
 * ManagerOrchestrator::manage() call threw at AIRequest construction and the
 * whole manager path was dead on arrival. Nothing had ever run it end to end.
 *
 * No database: this is a pure function over two arrays.
 *
 * © AI WebScapes 2026
 */
final class SchemaValidatorTest extends TestCase
{
    private function validator(): SchemaValidator
    {
        return new SchemaValidator();
    }

    public function test_accepts_a_matching_scalar_schema(): void
    {
        self::assertTrue($this->validator()->validate(
            ['verdict' => 'pass', 'confidence' => 1, 'score' => 1.5, 'ok' => true],
            ['verdict' => 'string', 'confidence' => 'int', 'score' => 'float', 'ok' => 'bool']
        ));
    }

    /**
     * An int satisfies a float field: JSON has one number type, so a model
     * answering 1 for a float is correct.
     */
    public function test_an_int_satisfies_a_float_field(): void
    {
        self::assertTrue($this->validator()->validate(['score' => 1], ['score' => 'float']));
    }

    public function test_a_float_does_not_satisfy_an_int_field(): void
    {
        self::assertFalse($this->validator()->validate(['count' => 1.5], ['count' => 'int']));
    }

    /**
     * The type the manager depends on. TaskDecomposer asks for
     * ['tasks' => 'array'] and ReviewLoop for ['findings' => 'array'].
     */
    public function test_accepts_a_list_for_an_array_field(): void
    {
        self::assertTrue($this->validator()->validate(
            ['tasks' => [['type' => 'generic']]],
            ['tasks' => 'array']
        ));
    }

    public function test_accepts_an_empty_list_for_an_array_field(): void
    {
        self::assertTrue(
            $this->validator()->validate(['findings' => []], ['findings' => 'array']),
            'a model that found nothing must be able to say so'
        );
    }

    /**
     * A JSON object also decodes to a PHP array. If `array` accepted it, a
     * caller would foreach over a string-keyed structure it did not expect.
     */
    public function test_rejects_an_object_for_an_array_field(): void
    {
        self::assertFalse(
            $this->validator()->validate(['tasks' => ['a' => 1]], ['tasks' => 'array']),
            'an object is not a list'
        );
    }

    public function test_rejects_a_scalar_for_an_array_field(): void
    {
        self::assertFalse($this->validator()->validate(['tasks' => 'nope'], ['tasks' => 'array']));
    }

    public function test_assert_schema_accepts_array_and_optional_array(): void
    {
        SchemaValidator::assertSchema(['tasks' => 'array']);
        SchemaValidator::assertSchema(['findings' => 'array?']);

        $this->expectNotToPerformAssertions();
    }

    public function test_assert_schema_rejects_an_unknown_type(): void
    {
        $this->expectException(InvalidArgumentException::class);

        SchemaValidator::assertSchema(['tasks' => 'list']);
    }

    public function test_assert_schema_rejects_an_empty_schema(): void
    {
        $this->expectException(InvalidArgumentException::class);

        SchemaValidator::assertSchema([]);
    }

    public function test_optional_fields_may_be_absent_but_not_null(): void
    {
        self::assertTrue(
            $this->validator()->validate(['a' => 'x'], ['a' => 'string', 'b' => 'string?']),
            'an optional field may be absent'
        );

        self::assertFalse(
            $this->validator()->validate(['a' => 'x', 'b' => null], ['a' => 'string', 'b' => 'string?']),
            'null is not the same as absent'
        );
    }

    public function test_rejects_an_unexpected_key(): void
    {
        self::assertFalse(
            $this->validator()->validate(['a' => 'x', 'extra' => 'y'], ['a' => 'string']),
            'a model that invents a field has misunderstood its instructions'
        );
    }

    public function test_reports_every_reason_not_just_the_first(): void
    {
        $errors = $this->validator()->errors(
            ['a' => 1, 'b' => 'x'],
            ['a' => 'string', 'b' => 'int']
        );

        self::assertCount(2, $errors, 'both mismatches must be reported for the review queue');
    }

    public function test_validates_a_nested_object_schema(): void
    {
        $schema = ['contact' => ['email' => 'string', 'name' => 'string?']];

        self::assertTrue($this->validator()->validate(['contact' => ['email' => 'a@b.test']], $schema));
        self::assertFalse($this->validator()->validate(['contact' => ['email' => 'a@b.test', 'name' => 1]], $schema));
        self::assertFalse($this->validator()->validate(['contact' => 'not-an-object'], $schema));
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function typeProvider(): iterable
    {
        yield 'string accepts string' => ['string', 'x', true];
        yield 'string rejects int' => ['string', '1', false];
        yield 'int accepts int' => ['int', '1', true];
        yield 'bool accepts bool' => ['bool', '1', true];
        yield 'bool rejects string' => ['bool', 'true', false];
    }

    #[DataProvider('typeProvider')]
    public function test_scalar_type_matching(string $type, string $raw, bool $expected): void
    {
        $value = match ($raw) {
            '1' => $type === 'string' ? 1 : ($type === 'bool' ? true : 1),
            'true' => 'true',
            default => $raw,
        };

        self::assertSame($expected, $this->validator()->validate(['f' => $value], ['f' => $type]));
    }
}
