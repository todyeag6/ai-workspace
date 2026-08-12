<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\AI\AIRequest;
use App\Deploy\LocalInferenceProfile;
use App\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * P4-T6 — Hybrid inference profile (AC-006: one control model across deploy models).
 * Resolves the AI base URL for local/hybrid from the SAME gateway seam; refuses a
 * `restricted` data-class call on the cloud path (SFR-SELF-003, reused not re-added).
 */
final class LocalInferenceProfileTest extends TestCase
{
    #[Test]
    public function test_local_binds_in_stack_ollama_url(): void
    {
        $profile = new LocalInferenceProfile();
        $url = $profile->resolveBaseUrl('local', 'http://ollama:11434/v1');
        self::assertSame('http://ollama:11434/v1', $url);
    }

    #[Test]
    public function test_hybrid_prefers_local_ollama_url(): void
    {
        $profile = new LocalInferenceProfile();
        $url = $profile->resolveBaseUrl('hybrid', 'http://ollama:11434/v1');
        self::assertSame('http://ollama:11434/v1', $url, 'Hybrid prefers the local on-prem model.');
    }

    #[Test]
    public function test_unknown_deployment_model_refused(): void
    {
        $profile = new LocalInferenceProfile();
        $this->expectException(\InvalidArgumentException::class);
        $profile->resolveBaseUrl('spaceship', 'http://ollama:11434/v1');
    }

    private function request(string $classification): AIRequest
    {
        // AIRequest(model, modelVersion, configVersion, purpose, tenantId,
        // dataClassification, tokenLimit, costLimitCents, costPerThousandTokensCents,
        // timeoutSeconds, outputSchema, prompt, promptTokens) — FR-AI-002 requires all.
        return new AIRequest(
            'hybrid-burst',
            '1.0',
            'v1',
            'lead_summarize',
            1,
            $classification,
            8192,
            5,
            1,
            30,
            ['summary' => 'string'],
            'summarize this lead'
        );
    }

    #[Test]
    public function test_restricted_data_class_refuses_cloud_egress(): void
    {
        // SFR-SELF-003 already enforced by CloudAdapter; the profile must route a
        // restricted-class request AWAY from any cloud URL regardless of deployment.
        $profile = new LocalInferenceProfile();
        self::assertFalse(
            $profile->mayUseCloud($this->request('restricted')),
            'A restricted-class request must never take the cloud egress path.'
        );
    }

    #[Test]
    public function test_non_restricted_hybrid_may_use_cloud(): void
    {
        $profile = new LocalInferenceProfile();
        self::assertTrue(
            $profile->mayUseCloud($this->request('internal')),
            'Non-restricted hybrid may burst to cloud.'
        );
    }
}
