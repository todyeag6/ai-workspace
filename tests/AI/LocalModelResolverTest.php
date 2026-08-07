<?php

declare(strict_types=1);

namespace App\Tests\AI;

use App\AI\ContextLimitExceeded;
use App\AI\LocalModelResolver;
use App\Tests\TestCase;
use InvalidArgumentException;

/**
 * P1-T7.5: which LOCAL model serves a need, and the context ceiling the
 * runtime will actually honour.
 *
 *   FR-AI-001  ModelRouter picks the runtime (local | cloud | review); this
 *              resolver picks the model INSIDE the local runtime. The two are
 *              separate decisions and are tested separately.
 *   FR-AI-004  An embedding need resolves to the embedding model rather than
 *              to a chat model that would answer the question instead of
 *              vectorising it.
 *
 * WHY THE POLICY IS SHAPED THIS WAY (verified live against Ollama :11434 on
 * 2026-08-07): the box runs OLLAMA_MAX_LOADED_MODELS=1, so exactly ONE model
 * is resident and every switch is an unload+reload. hermes3:8b is therefore
 * the single always-on resident and the answer to every general need; the
 * other entries are deliberate, named exceptions.
 *
 * gemma4:12b is the security-relevant case: it is an offload model and must
 * NEVER be auto-selected, so it is absent from the need->model map entirely
 * and reachable only through the explicit on-demand argument (AC-002
 * allowlist: nothing outside the approved set is ever returned).
 *
 * NO TEST HERE TOUCHES THE NETWORK: the policy is a table and an env read.
 *
 * © AI WebScapes 2026
 */
final class LocalModelResolverTest extends TestCase
{
    /**
     * Every general-purpose need lands on the one resident model. If this
     * fails, the box is thrashing weights between calls.
     */
    public function test_resolver_prevalent_model_is_hermes3(): void
    {
        $this->assertSame('hermes3:8b', (new LocalModelResolver())->resolve('standard'));
        $this->assertSame('hermes3:8b', (new LocalModelResolver())->resolve('quality'));
        $this->assertSame('hermes3:8b', (new LocalModelResolver())->resolve('coding'));
        $this->assertSame('hermes3:8b', (new LocalModelResolver())->resolve('reasoning'));
    }

    public function test_resolver_light_bulk_fallback(): void
    {
        $this->assertSame('qwen3:4b', (new LocalModelResolver())->resolve('light'));
    }

    public function test_resolver_quality_alt_offload(): void
    {
        $this->assertSame('qwen3.5-9b:8k', (new LocalModelResolver())->resolve('quality_alt'));
    }

    public function test_resolver_embedding_model(): void
    {
        $this->assertSame('nomic-embed-text', (new LocalModelResolver())->resolve('embed'));
    }

    /**
     * The allowlist inverted: no ordinary need may reach the offload model,
     * whatever the map says today.
     */
    public function test_resolver_never_auto_selects_gemma4(): void
    {
        $needs = ['standard', 'quality', 'coding', 'reasoning', 'light', 'quality_alt', 'embed'];

        foreach ($needs as $need) {
            $this->assertNotSame('gemma4:12b', (new LocalModelResolver())->resolve($need));
        }
    }

    public function test_resolver_gemma4_only_on_demand(): void
    {
        $this->assertSame(
            'gemma4:12b',
            (new LocalModelResolver())->resolve('standard', 'gemma4:12b')
        );
    }

    public function test_resolver_rejects_unknown_need(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new LocalModelResolver())->resolve('bogus');
    }

    /**
     * An unrecognised on-demand name is a typo or an attempt to pull an
     * unapproved model: refuse rather than pass it through to the runtime.
     */
    public function test_resolver_rejects_unknown_on_demand_model(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new LocalModelResolver())->resolve('standard', 'llama9:70b');
    }

    /**
     * Harness compatibility: the adapter forwards max_tokens verbatim, so a
     * request over the runtime ceiling would pass the gateway budget check
     * and only then 400 at Ollama. Catch it here instead.
     */
    public function test_context_ceiling_enforced_from_env(): void
    {
        $resolver = new LocalModelResolver();

        $this->assertSame(8192, $resolver->maxContextTokens());
        $resolver->assertWithinContext(8000);
        $resolver->assertWithinContext(8192);

        $this->expectException(ContextLimitExceeded::class);
        $resolver->assertWithinContext(9000);
    }

    /**
     * The ceiling is READ from the environment, not hard-coded: raising
     * OLLAMA_CONTEXT_LENGTH on a bigger box must move the limit, and a blank
     * or nonsense value must fall back to the 8192 this box runs.
     */
    public function test_context_ceiling_reads_env_with_fallback(): void
    {
        $original = getenv('OLLAMA_CONTEXT_LENGTH');

        try {
            putenv('OLLAMA_CONTEXT_LENGTH=4096');
            $this->assertSame(4096, (new LocalModelResolver())->maxContextTokens());

            putenv('OLLAMA_CONTEXT_LENGTH=not-a-number');
            $this->assertSame(8192, (new LocalModelResolver())->maxContextTokens());

            putenv('OLLAMA_CONTEXT_LENGTH=');
            $this->assertSame(8192, (new LocalModelResolver())->maxContextTokens());
        } finally {
            if (is_string($original)) {
                putenv('OLLAMA_CONTEXT_LENGTH=' . $original);
            } else {
                putenv('OLLAMA_CONTEXT_LENGTH');
            }
        }
    }

    /**
     * Fail-safe, not fail-quiet: an over-ceiling limit is refused with the
     * numbers in the message. Clamping would silently truncate the reasoning
     * and hand back a degraded answer that looks like a normal one.
     */
    public function test_over_ceiling_refuses_rather_than_clamping(): void
    {
        $resolver = new LocalModelResolver();

        try {
            $resolver->assertWithinContext(32000);
            $this->fail('Expected ContextLimitExceeded for a limit above the runtime ceiling.');
        } catch (ContextLimitExceeded $e) {
            $this->assertStringContainsString('32000', $e->getMessage());
            $this->assertStringContainsString('8192', $e->getMessage());
        }
    }
}
