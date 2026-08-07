<?php

declare(strict_types=1);

namespace App\AI;

use InvalidArgumentException;

/**
 * Chooses WHICH on-premises model serves a need, and enforces the context
 * window that model's runtime actually has (FR-AI-001, FR-AI-004).
 *
 * ModelRouter answers "local, cloud or a human?". This answers the next
 * question - "local WHICH?" - and they are kept apart because they fail for
 * different reasons: the router's input is fleet health, this one's input is
 * a capacity and security policy that changes when the hardware does.
 *
 * THE POLICY, verified live against Ollama :11434 on 2026-08-07:
 *
 *   OLLAMA_MAX_LOADED_MODELS=1 and OLLAMA_NUM_PARALLEL=1. Exactly ONE model is
 *   resident; asking for a second unloads the first and reloads from disk.
 *   Every avoidable switch is therefore paid for in seconds of latency by
 *   whoever is waiting, so the policy is deliberately boring:
 *
 *   - hermes3:8b is the SINGLE RESIDENT model and the answer to every general
 *     need - standard, quality, coding, reasoning. 8B, tools-capable, strong
 *     enough at all four that splitting them across models would buy accuracy
 *     nobody asked for and pay for it with a reload on every hop.
 *   - qwen3:4b serves 'light': bulk work where the answer is cheap and the
 *     wait is the cost.
 *   - qwen3.5-9b:8k serves 'quality_alt': the explicitly requested local
 *     second opinion. It offloads, so it is never the default.
 *   - nomic-embed-text serves 'embed'. An embedding need routed to a chat
 *     model gets prose back instead of a vector (FR-AI-004).
 *
 * SECURITY (AC-002, allowlist): the MAP below is the exhaustive set of models
 * this resolver will ever return on its own. gemma4:12b - the 12B
 * vision/audio offload model - appears NOWHERE in it and cannot be reached by
 * any need string, however crafted; it is available only when a caller names
 * it through $onDemandModel, which is a deliberate, auditable act. An unknown
 * need or an unknown on-demand name is refused rather than defaulted, because
 * a resolver that guesses is a resolver that runs an unapproved model.
 *
 * THE CEILING IS READ, NOT ASSUMED: OLLAMA_CONTEXT_LENGTH governs what the
 * runtime will accept, and the adapter forwards a request's token limit
 * verbatim. Without this check an over-ceiling call clears the gateway's
 * budget check and fails at the wire, after the work of building it.
 *
 * Stateless and dependency-free by design: this is a policy table plus an env
 * read, so it can be constructed anywhere it is needed without wiring.
 *
 * © AI WebScapes 2026
 */
final class LocalModelResolver
{
    /**
     * The ceiling this box runs. Used when the environment says nothing
     * usable - a resolver that returned "unlimited" on a missing variable
     * would disable the very check it exists to perform.
     */
    public const DEFAULT_CONTEXT_TOKENS = 8192;

    private const CONTEXT_ENV = 'OLLAMA_CONTEXT_LENGTH';

    /**
     * The exhaustive need -> model allowlist. Note gemma4:12b's absence: it is
     * not an oversight, it is the control.
     *
     * @var array<string, string>
     */
    private const MAP = [
        'standard' => 'hermes3:8b',
        'quality' => 'hermes3:8b',
        'coding' => 'hermes3:8b',
        'reasoning' => 'hermes3:8b',
        'light' => 'qwen3:4b',
        'quality_alt' => 'qwen3.5-9b:8k',
        'embed' => 'nomic-embed-text',
    ];

    /**
     * Models a caller may name explicitly: everything installed on the box.
     * gemma4:12b is here and only here - naming it is the sole route to it.
     *
     * @var list<string>
     */
    private const ON_DEMAND_ALLOWED = [
        'hermes3:8b',
        'qwen3:4b',
        'qwen3.5-9b:8k',
        'gemma4:12b',
        'nomic-embed-text',
    ];

    /**
     * @param  string      $need          standard | quality | coding |
     *                                    reasoning | light | quality_alt |
     *                                    embed.
     * @param  string|null $onDemandModel An explicitly requested model, which
     *                                    overrides the mapped choice. The only
     *                                    way to reach gemma4:12b.
     * @return string The model name to send to the local runtime.
     *
     * @throws InvalidArgumentException On a need with no mapping, or an
     *                                  on-demand name outside the approved
     *                                  set - either would otherwise reach the
     *                                  runtime as an unvetted model name.
     */
    public function resolve(string $need, ?string $onDemandModel = null): string
    {
        $mapped = self::MAP[$need] ?? null;

        if ($mapped === null) {
            throw new InvalidArgumentException(sprintf(
                'Unknown local model need "%s". Allowed: %s.',
                $need,
                implode(', ', array_keys(self::MAP))
            ));
        }

        if ($onDemandModel === null) {
            return $mapped;
        }

        if (!in_array($onDemandModel, self::ON_DEMAND_ALLOWED, true)) {
            throw new InvalidArgumentException(sprintf(
                'Refusing the on-demand model "%s": it is not in the approved '
                . 'local model set (%s).',
                $onDemandModel,
                implode(', ', self::ON_DEMAND_ALLOWED)
            ));
        }

        return $onDemandModel;
    }

    /**
     * The largest token limit the local runtime will honour, taken from
     * OLLAMA_CONTEXT_LENGTH. A missing, blank, non-numeric or non-positive
     * value falls back to the configured default rather than being trusted.
     */
    public function maxContextTokens(): int
    {
        $raw = getenv(self::CONTEXT_ENV);

        if (!is_string($raw)) {
            return self::DEFAULT_CONTEXT_TOKENS;
        }

        $trimmed = trim($raw);

        if ($trimmed === '' || ctype_digit($trimmed) === false) {
            return self::DEFAULT_CONTEXT_TOKENS;
        }

        $tokens = (int) $trimmed;

        return $tokens > 0 ? $tokens : self::DEFAULT_CONTEXT_TOKENS;
    }

    /**
     * @throws ContextLimitExceeded When the declared limit is larger than the
     *                              runtime window. Deliberately a refusal and
     *                              not a clamp: see ContextLimitExceeded.
     */
    public function assertWithinContext(int $tokenLimit): void
    {
        $ceiling = $this->maxContextTokens();

        if ($tokenLimit > $ceiling) {
            throw ContextLimitExceeded::overCeiling($tokenLimit, $ceiling);
        }
    }
}
