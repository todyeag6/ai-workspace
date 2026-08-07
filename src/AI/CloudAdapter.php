<?php

declare(strict_types=1);

namespace App\AI;

use App\Config\Secrets;
use Closure;
use InvalidArgumentException;
use RuntimeException;

/**
 * Runs a call against a hosted OpenAI-compatible provider (FR-AI-001).
 *
 * Identical to LocalAdapter from the gateway's point of view - that is what
 * ModelAdapter is for - and deliberately NOT identical in what it will carry:
 *
 *   1. RESTRICTED DATA HAS NO EGRESS PATH (FR-AI-005). A request classified
 *      'restricted' is refused here, before a body is built, so no prompt, no
 *      configuration mistake and no clever caller can send it off premises.
 *      The check lives in requestBody() rather than only in generate() so the
 *      refusal also covers anyone who builds a body and posts it themselves.
 *   2. TLS IS MANDATORY. A plaintext cloud base URL is a configuration error,
 *      not a warning: client material would cross the public internet in the
 *      clear and no runtime check could undo it.
 *   3. AN API KEY IS REQUIRED at construction. An adapter built without one
 *      would fail on its first real call, in production, at the least
 *      convenient moment.
 *
 * Local remains the default (ModelRouter): this class is the fallback, chosen
 * when the on-premises runtime cannot serve the call.
 *
 * See LocalAdapter on why the plumbing is duplicated rather than inherited -
 * a shared parent is precisely where the three rules above would erode.
 *
 * © AI WebScapes 2026
 */
final class CloudAdapter implements ModelAdapter
{
    public const ENV_BASE_URL = 'AI_CLOUD_BASE_URL';
    public const ENV_API_KEY = 'AI_CLOUD_API_KEY';

    /**
     * The classification that must never leave the premises. 'confidential'
     * deliberately still may: it is the ordinary class for client business
     * data, and refusing it would leave the cloud path unusable and therefore
     * routed around. 'restricted' is the class that means "this one does not
     * travel".
     */
    private const NO_EGRESS_CLASSIFICATION = 'restricted';

    private readonly string $endpoint;

    private readonly string $apiKey;

    /**
     * @var Closure(string, string, list<string>, int): string
     */
    private readonly Closure $transport;

    /**
     * @param string                                                    $baseUrl   e.g. https://api.provider.test
     *                                                                             or https://api.provider.test/v1.
     * @param string                                                    $apiKey    Never hardcoded; comes from the
     *                                                                             environment (FR-CONF-001).
     * @param (Closure(string, string, list<string>, int): string)|null $transport url, body, headers, timeout
     *                                                                             seconds -> raw response body.
     *
     * @throws InvalidArgumentException When the base URL is empty or not HTTPS, or the key is blank.
     */
    public function __construct(string $baseUrl, string $apiKey, ?Closure $transport = null)
    {
        $this->endpoint = self::resolveEndpoint($baseUrl);

        if (trim($apiKey) === '') {
            throw new InvalidArgumentException(sprintf(
                'A cloud provider API key is required (%s); refusing to build an adapter '
                . 'that can only fail on its first real call.',
                self::ENV_API_KEY
            ));
        }

        $this->apiKey = trim($apiKey);
        $this->transport = $transport ?? self::defaultTransport();
    }

    /**
     * @param array<string, mixed>                                      $env
     * @param (Closure(string, string, list<string>, int): string)|null $transport
     */
    public static function fromEnvironment(array $env, ?Closure $transport = null): self
    {
        $secrets = new Secrets($env);

        return new self(
            $secrets->require(self::ENV_BASE_URL),
            $secrets->require(self::ENV_API_KEY),
            $transport
        );
    }

    public function endpoint(): string
    {
        return $this->endpoint;
    }

    /**
     * The OpenAI-compatible chat-completion body for $request.
     *
     * @throws RuntimeException When the request carries data that must not
     *                          leave the premises (FR-AI-005).
     */
    public function requestBody(AIRequest $request): string
    {
        $this->assertEgressPermitted($request);

        return (string) json_encode(
            [
                'model' => $request->model(),
                'messages' => [
                    [
                        'role' => 'system',
                        'content' => InjectionFilter::instructionHierarchyPreamble(),
                    ],
                    [
                        'role' => 'user',
                        'content' => $request->prompt(),
                    ],
                ],
                'max_tokens' => $request->tokenLimit(),
                'temperature' => 0,
                'stream' => false,
            ],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
    }

    /**
     * @throws RuntimeException When egress is refused, or the provider cannot
     *                          be reached at all.
     */
    public function generate(AIRequest $request): string
    {
        $response = ($this->transport)(
            $this->endpoint,
            $this->requestBody($request),
            $this->headers(),
            $request->timeoutSeconds()
        );

        return self::unwrap($response);
    }

    /**
     * @throws RuntimeException Always, for restricted data.
     */
    private function assertEgressPermitted(AIRequest $request): void
    {
        if ($request->dataClassification() !== self::NO_EGRESS_CLASSIFICATION) {
            return;
        }

        throw new RuntimeException(sprintf(
            'Refusing to send %s data for tenant %d to a hosted provider (%s). FR-AI-005 '
            . 'keeps restricted material on premises - route this call to the local '
            . 'runtime or leave it for review.',
            self::NO_EGRESS_CLASSIFICATION,
            $request->tenantId(),
            $this->endpoint
        ));
    }

    /**
     * @return list<string>
     */
    private function headers(): array
    {
        return [
            'Content-Type: application/json',
            'Accept: application/json',
            'Authorization: Bearer ' . $this->apiKey,
        ];
    }

    /**
     * @throws InvalidArgumentException When the URL is unusable or plaintext.
     */
    private static function resolveEndpoint(string $baseUrl): string
    {
        $base = rtrim(trim($baseUrl), '/');

        if ($base === '') {
            throw new InvalidArgumentException(sprintf(
                'A cloud provider base URL is required (%s); refusing to guess one.',
                self::ENV_BASE_URL
            ));
        }

        if (!str_starts_with($base, 'https://')) {
            throw new InvalidArgumentException(sprintf(
                'The cloud provider base URL must be https://, got "%s". Client material '
                . 'does not cross the public internet in the clear.',
                $baseUrl
            ));
        }

        if (str_ends_with($base, '/chat/completions')) {
            return $base;
        }

        return str_ends_with($base, '/v1')
            ? $base . '/chat/completions'
            : $base . '/v1/chat/completions';
    }

    /**
     * See LocalAdapter::unwrap(): an unrecognised envelope is passed through
     * so the gateway sends it to review with the evidence intact.
     */
    private static function unwrap(string $response): string
    {
        $decoded = json_decode($response, true);

        if (!is_array($decoded) || !isset($decoded['choices']) || !is_array($decoded['choices'])) {
            return $response;
        }

        $first = $decoded['choices'][0] ?? null;

        if (!is_array($first) || !isset($first['message']) || !is_array($first['message'])) {
            return $response;
        }

        $content = $first['message']['content'] ?? null;

        return is_string($content) ? $content : $response;
    }

    /**
     * @return Closure(string, string, list<string>, int): string
     */
    private static function defaultTransport(): Closure
    {
        return static function (string $url, string $body, array $headers, int $timeoutSeconds): string {
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => implode("\r\n", $headers),
                    'content' => $body,
                    'timeout' => $timeoutSeconds,
                    'ignore_errors' => true,
                ],
            ]);

            $response = @file_get_contents($url, false, $context);

            if ($response === false) {
                throw new RuntimeException(sprintf(
                    'No response from the cloud provider at %s within %d seconds.',
                    $url,
                    $timeoutSeconds
                ));
            }

            return $response;
        };
    }
}
