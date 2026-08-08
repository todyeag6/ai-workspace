<?php

declare(strict_types=1);

namespace App\Connectors;

use Closure;

/**
 * Executes a tool call against an HTTP connector (P2-T2). Covers `http_fetch`
 * and `webhook`.
 *
 * The only destination is $spec->baseUrl, taken from the vetted `connectors`
 * catalogue - never from a model-supplied URL. (ToolGateway already refused any
 * parameter URL outside the egress allowlist; this client does not re-litigate
 * that, it just never looks at a model URL to begin with.)
 *
 * The transport is injected, so the unit tests exercise request assembly and
 * response mapping without opening a socket. The default transport is a real
 * curl POST, mirroring the adapters' pattern.
 *
 * © AI WebScapes 2026
 */
final class HttpConnectorClient implements ConnectorClient
{
    /**
     * @param Closure(string $method, string $url, array<string, mixed> $body): array<string, mixed> $transport
     */
    public function __construct(private readonly Closure $transport)
    {
    }

    public function supports(string $type): bool
    {
        return $type === 'http';
    }

    public function execute(ConnectorSpec $spec, array $params): array
    {
        // The path/query come from the already-validated params, the host never
        // does. baseUrl is the sole egress target.
        $path = ($params['path'] ?? '') !== '' ? (string) $params['path'] : '';
        $url = rtrim($spec->baseUrl, '/') . ($path !== '' ? '/' . ltrim($path, '/') : '');
        $method = ($params['method'] ?? '') !== '' ? strtoupper((string) $params['method']) : 'POST';

        $body = $params['body'] ?? $params;

        $raw = ($this->transport)($method, $url, $body);

        return [
            'status' => (string) ($raw['status'] ?? 'ok'),
            'payload' => $raw['payload'] ?? null,
            'connector' => $spec->name,
        ];
    }
}
