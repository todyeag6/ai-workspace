<?php

/**
 * Hybrid inference profile (P4-T6).
 *
 * Resolves the AI base URL for the local/hybrid deployment models and decides
 * whether a given request may take the cloud egress path. It does NOT implement
 * routing — ModelRouter already does that (FR-AI-001) — it only binds the
 * in-stack Ollama URL for local/hybrid and re-applies the SFR-SELF-003
 * refusal for `restricted` data (CloudAdapter refuses it too; this is defence
 * in depth at the deployment-profile layer, one control model per AC-006).
 */

declare(strict_types=1);

namespace App\Deploy;

use App\AI\AIRequest;
use InvalidArgumentException;

final class LocalInferenceProfile
{
    /** @var list<string> Deployment models this profile understands (AC-006 set). */
    private const MODELS = ['local', 'hybrid', 'cloud', 'client-cloud'];

    /**
     * Resolve the base URL for a deployment model.
     *
     * @return string The in-stack Ollama URL for local/hybrid (the
     *                caller passes it; this class validates it is the
     *                local service, not an external endpoint).
     *
     * @throws InvalidArgumentException On an unknown deployment model or a
     *                                  non-local URL for a local deployment.
     */
    public function resolveBaseUrl(string $deploymentModel, string $localOllamaUrl): string
    {
        if (!in_array($deploymentModel, self::MODELS, true)) {
            throw new InvalidArgumentException(sprintf('Unknown deployment_model: %s', $deploymentModel));
        }

        if (($deploymentModel === 'local' || $deploymentModel === 'hybrid')
            && !str_starts_with($localOllamaUrl, 'http://ollama')
            && !str_starts_with($localOllamaUrl, 'http://host.docker.internal')) {
            throw new InvalidArgumentException(
                'Local/hybrid deployment must bind the in-stack or host-local Ollama URL.'
            );
        }

        return $localOllamaUrl;
    }

    /**
     * Whether a request may use the cloud egress path under this profile.
     * `restricted` data class is never permitted off-premises (SFR-SELF-003).
     */
    public function mayUseCloud(AIRequest $request): bool
    {
        return $request->dataClassification() !== 'restricted';
    }
}
