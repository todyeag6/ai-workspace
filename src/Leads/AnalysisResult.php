<?php

declare(strict_types=1);

namespace App\Leads;

/**
 * One model verdict about one lead, in the agreed schema (LFR-AI-001).
 *
 * A value object rather than the model's raw array on purpose: the array a
 * model returns is UNTRUSTED and arbitrarily shaped, and every consumer that
 * reads it directly grows its own defensive guesswork about which keys exist.
 * Parsing once, here, means a missing or malformed key is resolved in a single
 * place and the rest of the system reads a fixed, typed shape.
 *
 * `status` is deliberately NOT part of toArray(): the eight schema fields are
 * what the model said, `status` is what THIS system decided to do about it
 * (LFR-AI-003 - anything below LeadService::MIN_CONFIDENCE goes to a human).
 * Keeping the two apart stops a low-confidence verdict from being read back
 * later as though the model itself had asked for review.
 *
 * © AI WebScapes 2026
 */
final class AnalysisResult
{
    /**
     * @param list<string> $riskFlags
     */
    public function __construct(
        public readonly string $summary,
        public readonly string $intent,
        public readonly string $category,
        public readonly string $urgency,
        public readonly string $nextStep,
        public readonly array $riskFlags,
        public readonly float $confidence,
        public readonly string $rationale,
        public readonly string $status
    ) {
    }

    /**
     * The eight schema fields, snake_cased as they are stored and transported.
     *
     * @return array{
     *     summary: string,
     *     intent: string,
     *     category: string,
     *     urgency: string,
     *     next_step: string,
     *     risk_flags: list<string>,
     *     confidence: float,
     *     rationale: string
     * }
     */
    public function toArray(): array
    {
        return [
            'summary' => $this->summary,
            'intent' => $this->intent,
            'category' => $this->category,
            'urgency' => $this->urgency,
            'next_step' => $this->nextStep,
            'risk_flags' => $this->riskFlags,
            'confidence' => $this->confidence,
            'rationale' => $this->rationale,
        ];
    }
}
