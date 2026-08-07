<?php

declare(strict_types=1);

namespace App\AI;

use App\Config\Secrets;
use Closure;
use InvalidArgumentException;
use RuntimeException;

/**
 * Runs a call against the on-premises OpenAI-compatible runtime - Ollama,
 * llama.cpp's server, vLLM (FR-AI-001).
 *
 * This is the DEFAULT half of local-first routing (see ModelRouter): it serves
 * every data classification, including 'restricted', because nothing it sends
 * leaves the premises. CloudAdapter is the constrained one.
 *
 * WHY THE TRANSPORT IS INJECTABLE: the alternative is an adapter that can only
 * be exercised with a model server running, which means the wire format - the
 * part most likely to be quietly wrong - is only ever checked by hand. A
 * closure seam lets the request shape be asserted in an ordinary unit test and
 * costs one optional constructor argument. The default is a real HTTP POST, so
 * production wiring stays `new LocalAdapter($baseUrl)`.
 *
 * WHY NEARLY THE SAME CODE APPEARS IN CloudAdapter: the two differ in what
 * they are ALLOWED to send, not much in how they send it. A shared parent
 * would be exactly the place where a later "small refactor" grants the cloud
 * this class's tolerance for restricted data, and that mistake would be
 * invisible in the diff of a base class nobody re-reads. A dozen duplicated
 * lines of plumbing is a cheaper price than that failure mode.
 *
 * NO RETRIES, per the ModelAdapter contract: a silent retry doubles the token
 * spend the gateway just authorised against the request's budget.
 *
 * © AI WebScapes 2026
 */
final class LocalAdapter implements ModelAdapter
{
    public const ENV_BASE_URL = 'AI_LOCAL_BASE_URL';

    private readonly string $endpoint;

    /**
     * @var Closure(string, string, list<string>, int): string
     */
    private readonly Closure $transport;

    /**
     * @param string                                                     $baseUrl   Root of the runtime, e.g.
     *                                                                              http://ollama:11434. Never
     *                                                                              hardcoded: deployments differ.
     * @param (Closure(string, string, list<string>, int): string)|null  $transport url, body, headers, timeout
     *                                                                              seconds -> raw response body.
     *
     * @throws InvalidArgumentException When the base URL is empty or not HTTP(S).
     */
    public function __construct(string $baseUrl, ?Closure $transport = null)
    {
        $this->endpoint = self::resolveEndpoint($baseUrl);
        $this->transport = $transport ?? self::defaultTransport();
    }

    /**
     * Builds the adapter from the environment, failing closed when the base
     * URL is absent (FR-CONF-002) rather than defaulting to localhost - a
     * default here would silently point production at nothing.
     *
     * @param array<string, mixed>                                      $env
     * @param (Closure(string, string, list<string>, int): string)|null $transport
     */
    public static function fromEnvironment(array $env, ?Closure $transport = null): self
    {
        return new self((new Secrets($env))->require(self::ENV_BASE_URL), $transport);
    }

    /**
     * The exact URL this adapter will POST to. Public so routing and
     * configuration can be asserted without a live server.
     */
    public function endpoint(): string
    {
        return $this->endpoint;
    }

    /**
     * The OpenAI-compatible chat-completion body for $request.
     *
     * Public for the same reason as endpoint(): the wire format is part of
     * this class's contract, and a format that can only be observed by
     * watching real traffic is one that regresses unnoticed.
     */
    public function requestBody(AIRequest $request): string
    {
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
     * @throws RuntimeException When the runtime cannot be reached at all.
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
     * @return list<string>
     */
    private function headers(): array
    {
        return [
            'Content-Type: application/json',
            'Accept: application/json',
        ];
    }

    /**
     * Normalises a configured base URL to the chat-completions endpoint,
     * tolerating the three forms operators actually write: bare host, host
     * plus /v1, and the full endpoint.
     *
     * @throws InvalidArgumentException When the URL is unusable.
     */
    private static function resolveEndpoint(string $baseUrl): string
    {
        $base = rtrim(trim($baseUrl), '/');

        if ($base === '') {
            throw new InvalidArgumentException(sprintf(
                'A local model base URL is required (%s); refusing to guess one.',
                self::ENV_BASE_URL
            ));
        }

        if (!str_starts_with($base, 'http://') && !str_starts_with($base, 'https://')) {
            throw new InvalidArgumentException(sprintf(
                'The local model base URL must be http:// or https://, got "%s".',
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
     * Pulls the model's own output out of the provider envelope.
     *
     * An envelope that does not match the OpenAI shape - an HTML error page, a
     * gateway timeout, a provider that changed its response - is returned
     * UNCHANGED rather than throwing, so AIGateway's fail-safe dispositions it
     * to 'review' with the raw text attached. Throwing here would turn a
     * provider hiccup into an unhandled error and lose the evidence.
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
     * A plain POST over the http(s) stream wrapper. No curl extension is
     * required, and ignore_errors keeps a 4xx/5xx BODY readable instead of
     * collapsing it to false, which is what makes a provider error reviewable.
     *
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
                    'No response from the local model runtime at %s within %d seconds.',
                    $url,
                    $timeoutSeconds
                ));
            }

            return $response;
        };
    }
}
