<?php

declare(strict_types=1);

namespace App\Connectors;

use Closure;

/**
 * Executes a CRM connector call (P2-T2). Covers `crm_lookup`.
 *
 * Builds a CRM read against the connector's base_url and funnels it through
 * the same injected transport as the HTTP client - the CRM system IS an HTTP
 * API, this class only knows how to shape a CRM query (object + id/email) and
 * read back the record. It performs no auth decisions; credentials are a
 * scoped secret resolved by the transport, not passed in params.
 *
 * © AI WebScapes 2026
 */
final class CrmConnectorClient implements ConnectorClient
{
    /**
     * @param Closure(string $method, string $url, array<string, mixed> $body): array<string, mixed> $transport
     */
    public function __construct(private readonly Closure $transport)
    {
    }

    public function supports(string $type): bool
    {
        return $type === 'crm';
    }

    public function execute(ConnectorSpec $spec, array $params): array
    {
        $object = ($params['object'] ?? '') !== '' ? (string) $params['object'] : 'contact';
        $id = ($params['id'] ?? '') !== ''
            ? (string) $params['id']
            : (($params['email'] ?? '') !== '' ? (string) $params['email'] : '');

        if ($id === '') {
            return [
                'status' => 'error',
                'payload' => ['message' => 'crm_lookup requires an id or email'],
                'connector' => $spec->name,
            ];
        }

        $url = rtrim($spec->baseUrl, '/') . '/crm/v3/objects/' . $object . '/' . rawurlencode($id);
        $raw = ($this->transport)('GET', $url, []);

        return [
            'status' => (string) ($raw['status'] ?? 'ok'),
            'payload' => $raw['payload'] ?? null,
            'connector' => $spec->name,
        ];
    }
}
