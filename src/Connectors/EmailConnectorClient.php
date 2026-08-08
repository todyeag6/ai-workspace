<?php

declare(strict_types=1);

namespace App\Connectors;

use Closure;

/**
 * Executes an email connector call (P2-T2). Covers `send_email`.
 *
 * The recipient is already egress-validated by ToolGateway against the
 * allowlist; this client only assembles the message and pushes it through the
 * injected transport (which wraps the real SMTP/API submit). The connector's
 * base_url (e.g. smtp://smtp.aiwebscapes.test) is the sole egress target.
 *
 * © AI WebScapes 2026
 */
final class EmailConnectorClient implements ConnectorClient
{
    /**
     * @param Closure(string $method, string $url, array<string, mixed> $body): array<string, mixed> $transport
     */
    public function __construct(private readonly Closure $transport)
    {
    }

    public function supports(string $type): bool
    {
        return $type === 'email';
    }

    public function execute(ConnectorSpec $spec, array $params): array
    {
        $to = ($params['to'] ?? '') !== '' ? (string) $params['to']
            : (($params['recipient'] ?? '') !== '' ? (string) $params['recipient'] : '');
        $subject = ($params['subject'] ?? '') !== '' ? (string) $params['subject'] : '(no subject)';
        $body = ($params['body'] ?? '') !== '' ? (string) $params['body'] : '';

        if ($to === '') {
            return [
                'status' => 'error',
                'payload' => ['message' => 'send_email requires a recipient'],
                'connector' => $spec->name,
            ];
        }

        $raw = ($this->transport)('POST', $spec->baseUrl, [
            'to' => $to,
            'subject' => $subject,
            'body' => $body,
        ]);

        return [
            'status' => (string) ($raw['status'] ?? 'sent'),
            'payload' => $raw['payload'] ?? null,
            'connector' => $spec->name,
        ];
    }
}
