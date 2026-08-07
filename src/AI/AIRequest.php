<?php

declare(strict_types=1);

namespace App\AI;

use InvalidArgumentException;

/**
 * Everything FR-AI-002 requires a model call to state, in one immutable value
 * object: model and version, configuration version, purpose, tenant, data
 * classification, token and cost limits, timeout, and the schema the output is
 * expected to match.
 *
 * WHY EVERY ARGUMENT IS NULLABLE AND DEFAULTED, THEN CHECKED: PHP's own
 * "missing required argument" error is a fatal ArgumentCountError naming ONE
 * parameter at a time, so a caller who forgot four fields discovers them one
 * painful run apart. Accepting nulls and validating here reports the whole set
 * at once - and, more importantly, makes the requirement testable: FR-AI-002
 * is proven by constructing AIRequest(model: 'local') and catching the
 * refusal, which a signature of non-optional parameters could not express.
 *
 * NOTHING IS INFERRED FROM A DEFAULT. There is no default model, no default
 * tenant, no default token budget, no "sensible" 30-second timeout. A default
 * is a decision nobody reviewed, and the whole point of this class is that
 * every one of these decisions is on the record at the call site.
 *
 * THE ONE EXCEPTION IS promptTokens, which is DERIVED (not defaulted) from the
 * prompt when the caller does not measure it: an estimate that follows the
 * actual prompt cannot silently drift out of date the way a hard-coded number
 * would, and callers with a real tokeniser can still pass the exact count.
 *
 * WHY costPerThousandTokensCents IS REQUIRED although FR-AI-002 only names a
 * "cost limit": a cost limit with no rate attached cannot be enforced, so it
 * would be decoration. Local models declare 0 explicitly - the zero is stated,
 * not assumed.
 *
 * © AI WebScapes 2026
 */
final class AIRequest
{
    /**
     * Sensitivity of the data being sent to the model, which is what governs
     * whether a given deployment may serve the call at all. Orthogonal to
     * agents.data_classes (which lists WHICH kinds of data an agent touches).
     *
     * @var list<string>
     */
    private const DATA_CLASSIFICATIONS = ['public', 'internal', 'confidential', 'restricted'];

    /**
     * Rough characters-per-token for the fallback estimate. Deliberately
     * pessimistic-ish and deliberately crude: it exists so an unmeasured call
     * still has a number to check a budget against, not to be accurate.
     */
    private const CHARS_PER_TOKEN = 4;

    private string $model;

    private string $modelVersion;

    private string $configVersion;

    private string $purpose;

    private int $tenantId;

    private string $dataClassification;

    private int $tokenLimit;

    private int $costLimitCents;

    private int $costPerThousandTokensCents;

    private int $timeoutSeconds;

    /**
     * @var array<array-key, mixed>
     */
    private array $outputSchema;

    private string $prompt;

    private int $promptTokens;

    /**
     * @param  array<array-key, mixed>|null $outputSchema See SchemaValidator for the language.
     * @param  int|null                     $promptTokens Measured token count; estimated from
     *                                                    the prompt when null.
     * @throws InvalidArgumentException When any FR-AI-002 field is missing or nonsensical.
     */
    public function __construct(
        ?string $model = null,
        ?string $modelVersion = null,
        ?string $configVersion = null,
        ?string $purpose = null,
        ?int $tenantId = null,
        ?string $dataClassification = null,
        ?int $tokenLimit = null,
        ?int $costLimitCents = null,
        ?int $costPerThousandTokensCents = null,
        ?int $timeoutSeconds = null,
        ?array $outputSchema = null,
        ?string $prompt = null,
        ?int $promptTokens = null
    ) {
        $missing = [];

        foreach (
            [
                'model' => $model,
                'modelVersion' => $modelVersion,
                'configVersion' => $configVersion,
                'purpose' => $purpose,
                'tenantId' => $tenantId,
                'dataClassification' => $dataClassification,
                'tokenLimit' => $tokenLimit,
                'costLimitCents' => $costLimitCents,
                'costPerThousandTokensCents' => $costPerThousandTokensCents,
                'timeoutSeconds' => $timeoutSeconds,
                'outputSchema' => $outputSchema,
                'prompt' => $prompt,
            ] as $field => $value
        ) {
            if ($value === null || $value === '') {
                $missing[] = $field;
            }
        }

        if ($missing !== []) {
            throw new InvalidArgumentException(sprintf(
                'Refusing to build a model call missing %s. FR-AI-002 requires every '
                . 'call to state its model and version, configuration version, purpose, '
                . 'tenant, data classification, token and cost limits, timeout and '
                . 'expected output schema.',
                implode(', ', $missing)
            ));
        }

        // Narrowing for PHPStan and for the reader: past the guard above, none
        // of these can be null.
        assert($model !== null && $modelVersion !== null && $configVersion !== null);
        assert($purpose !== null && $tenantId !== null && $dataClassification !== null);
        assert($tokenLimit !== null && $costLimitCents !== null && $costPerThousandTokensCents !== null);
        assert($timeoutSeconds !== null && $outputSchema !== null && $prompt !== null);

        $this->assertPositive('tenantId', $tenantId);
        $this->assertPositive('tokenLimit', $tokenLimit);
        $this->assertPositive('timeoutSeconds', $timeoutSeconds);
        $this->assertNotNegative('costLimitCents', $costLimitCents);
        $this->assertNotNegative('costPerThousandTokensCents', $costPerThousandTokensCents);

        if (!in_array($dataClassification, self::DATA_CLASSIFICATIONS, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown data classification "%s". Allowed: %s.',
                $dataClassification,
                implode(', ', self::DATA_CLASSIFICATIONS)
            ));
        }

        // Fails here, at configuration time, rather than sending every output
        // of an unmatchable schema to review forever.
        SchemaValidator::assertSchema($outputSchema);

        if ($promptTokens !== null) {
            $this->assertNotNegative('promptTokens', $promptTokens);
        }

        $this->model = $model;
        $this->modelVersion = $modelVersion;
        $this->configVersion = $configVersion;
        $this->purpose = $purpose;
        $this->tenantId = $tenantId;
        $this->dataClassification = $dataClassification;
        $this->tokenLimit = $tokenLimit;
        $this->costLimitCents = $costLimitCents;
        $this->costPerThousandTokensCents = $costPerThousandTokensCents;
        $this->timeoutSeconds = $timeoutSeconds;
        $this->outputSchema = $outputSchema;
        $this->prompt = $prompt;
        $this->promptTokens = $promptTokens ?? (int) ceil(mb_strlen($prompt) / self::CHARS_PER_TOKEN);
    }

    public function model(): string
    {
        return $this->model;
    }

    public function modelVersion(): string
    {
        return $this->modelVersion;
    }

    /**
     * model@version, the string that belongs in an audit record: neither half
     * identifies a model run on its own.
     */
    public function modelIdentifier(): string
    {
        return $this->model . '@' . $this->modelVersion;
    }

    public function configVersion(): string
    {
        return $this->configVersion;
    }

    public function purpose(): string
    {
        return $this->purpose;
    }

    public function tenantId(): int
    {
        return $this->tenantId;
    }

    public function dataClassification(): string
    {
        return $this->dataClassification;
    }

    public function tokenLimit(): int
    {
        return $this->tokenLimit;
    }

    public function costLimitCents(): int
    {
        return $this->costLimitCents;
    }

    public function timeoutSeconds(): int
    {
        return $this->timeoutSeconds;
    }

    /**
     * @return array<array-key, mixed>
     */
    public function outputSchema(): array
    {
        return $this->outputSchema;
    }

    public function prompt(): string
    {
        return $this->prompt;
    }

    public function promptTokens(): int
    {
        return $this->promptTokens;
    }

    /**
     * Rounded UP: a budget check that rounded down would let a call through
     * for being a fraction of a cent under the line.
     */
    public function estimatedCostCents(): int
    {
        return (int) ceil($this->promptTokens * $this->costPerThousandTokensCents / 1000);
    }

    private function assertPositive(string $field, int $value): void
    {
        if ($value <= 0) {
            throw new InvalidArgumentException(sprintf(
                '%s must be greater than zero, got %d.',
                $field,
                $value
            ));
        }
    }

    private function assertNotNegative(string $field, int $value): void
    {
        if ($value < 0) {
            throw new InvalidArgumentException(sprintf(
                '%s must not be negative, got %d.',
                $field,
                $value
            ));
        }
    }
}
