<?php

declare(strict_types=1);

namespace App\Tests\AI;

use App\AI\AIGateway;
use App\AI\AIRequest;
use App\AI\ModelAdapter;
use App\AI\SchemaValidator;
use App\Tests\TestCase;
use ReflectionClass;
use ReflectionNamedType;
use ReflectionUnionType;

/**
 * P1-T6: the AI gateway and its schema-validated fail-safe.
 *
 *   FR-AI-002  A model call cannot be made without model/version, config
 *              version, purpose, tenant, data classification, token and cost
 *              limits, timeout and an expected output schema. Proven by
 *              constructing a request with only a model and catching the
 *              refusal, and by the budget check refusing before the adapter is
 *              ever reached.
 *   FR-AI-003  Structured output is validated BEFORE anything downstream sees
 *              it. Proven by a payload that parses as JSON but does not match
 *              the schema coming back invalid rather than being handed on.
 *   AC-003     An invalid output goes to disposition 'review' and fires NO
 *              side effect. The side-effect half is asserted STRUCTURALLY (see
 *              externalEffects()): a counter that the gateway simply never
 *              increments would pass no matter what the gateway did.
 *
 * © AI WebScapes 2026
 */
final class AIGatewayTest extends TestCase
{
    /**
     * The schema a lead-analysis call promises to return. Nested on purpose:
     * a validator that only checked top-level keys would pass everything the
     * flat cases throw at it and still be useless in production.
     *
     * @var array<string, mixed>
     */
    private const LEAD_SCHEMA = [
        'lead_score' => 'int',
        'category' => 'string',
        'follow_up_required' => 'bool',
        'contact' => [
            'email' => 'string',
            'name' => 'string?',
        ],
    ];

    /**
     * The only dependency types the gateway is allowed to hold. Anything else
     * (a PDO, a mailer, a tool gateway, an HTTP client) is an external effect
     * and makes externalEffects() non-zero.
     *
     * @var list<string>
     */
    private const PURE_DEPENDENCIES = [ModelAdapter::class, SchemaValidator::class];

    private AIGateway $gw;

    protected function setUp(): void
    {
        parent::setUp();

        $this->gw = new AIGateway($this->adapterReturning('{"bad":true}'), new SchemaValidator());
    }

    public function test_invalid_output_fails_safe_no_side_effect(): void
    {
        $gw = new AIGateway($this->adapterReturning('{"bad":true}'), new SchemaValidator());
        $r  = $gw->complete($this->leadAnalysisRequest());

        $this->assertFalse($r->valid);
        $this->assertSame('review', $r->disposition);
        $this->assertSame(0, $this->externalEffects());
        $this->assertNull($r->payload, 'An invalid output must not be handed downstream as a payload.');
        $this->assertSame('{"bad":true}', $r->raw, 'The raw output is kept so a reviewer can see it.');
    }

    public function test_request_requires_full_metadata(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new AIRequest(model: 'local');
    }

    public function test_token_and_cost_limits_enforced(): void
    {
        $this->expectException(\App\AI\BudgetExceeded::class);

        $this->gw->complete($this->requestWith(tokenLimit: 10, promptTokens: 5000));
    }

    /**
     * The happy path, without which every assertion above could be satisfied
     * by a gateway that returned 'review' unconditionally.
     */
    public function test_schema_valid_output_is_usable(): void
    {
        $json = '{"lead_score":81,"category":"enterprise","follow_up_required":true,'
            . '"contact":{"email":"cto@example.test","name":"Dana"}}';

        $gw = new AIGateway($this->adapterReturning($json), new SchemaValidator());
        $r  = $gw->complete($this->leadAnalysisRequest());

        $this->assertTrue($r->valid);
        $this->assertNotSame('review', $r->disposition);
        $this->assertSame(81, $r->payload['lead_score'] ?? null);
        $this->assertSame(0, $this->externalEffects());
    }

    /**
     * A stub model adapter that hands back exactly $json. It records nothing
     * and touches nothing: the seam is deliberately the only way out of the
     * gateway, so a stub here is a complete stand-in for the real thing.
     */
    private function adapterReturning(string $json): ModelAdapter
    {
        return new class ($json) implements ModelAdapter {
            public function __construct(private readonly string $json)
            {
            }

            public function generate(AIRequest $request): string
            {
                return $this->json;
            }
        };
    }

    /**
     * A fully specified request (FR-AI-002) whose schema the '{"bad":true}'
     * payload cannot satisfy.
     */
    private function leadAnalysisRequest(): AIRequest
    {
        return new AIRequest(
            model: 'llama3.1',
            modelVersion: '8b-instruct-q5',
            configVersion: '2026.02.1',
            purpose: 'Score and categorise an inbound lead',
            tenantId: 1,
            dataClassification: 'confidential',
            tokenLimit: 4000,
            costLimitCents: 50,
            costPerThousandTokensCents: 2,
            timeoutSeconds: 30,
            outputSchema: self::LEAD_SCHEMA,
            prompt: 'Analyse this lead: ACME Corp, 400 seats, inbound demo request.'
        );
    }

    /**
     * The same request with the budget knobs turned to whatever the caller is
     * proving.
     */
    private function requestWith(int $tokenLimit, int $promptTokens): AIRequest
    {
        return new AIRequest(
            model: 'llama3.1',
            modelVersion: '8b-instruct-q5',
            configVersion: '2026.02.1',
            purpose: 'Score and categorise an inbound lead',
            tenantId: 1,
            dataClassification: 'confidential',
            tokenLimit: $tokenLimit,
            costLimitCents: 50,
            costPerThousandTokensCents: 2,
            timeoutSeconds: 30,
            outputSchema: self::LEAD_SCHEMA,
            prompt: 'Analyse this lead: ACME Corp, 400 seats, inbound demo request.',
            promptTokens: $promptTokens
        );
    }

    /**
     * How many effectful collaborators the gateway holds.
     *
     * WHY REFLECTION AND NOT A COUNTER: a counter the gateway never touches
     * returns 0 for any implementation, including one that sends email in
     * complete(). Reading the class's own dependencies instead makes the
     * assertion falsifiable - adding a PDO, a mailer, an HTTP client or a tool
     * gateway to AIGateway turns this non-zero and fails AC-003 immediately.
     * A property with no type, or a union, is counted as an effect too: an
     * untyped seam is one nobody can audit.
     */
    private function externalEffects(): int
    {
        $effects = 0;

        foreach ((new ReflectionClass(AIGateway::class))->getProperties() as $property) {
            $type = $property->getType();

            if ($type instanceof ReflectionNamedType) {
                if ($type->isBuiltin()) {
                    continue;
                }

                if (!in_array($type->getName(), self::PURE_DEPENDENCIES, true)) {
                    $effects++;
                }

                continue;
            }

            if ($type instanceof ReflectionUnionType) {
                $effects++;

                continue;
            }

            // Untyped property: unauditable, so treated as an effect.
            $effects++;
        }

        return $effects;
    }
}
