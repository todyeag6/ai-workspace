<?php

declare(strict_types=1);

namespace App\Leads;

/**
 * The redacted payload handed to the model (LFR-AI-002).
 *
 * ALLOW-LIST, NOT DENY-LIST. This object can only be built by
 * LeadService::buildAIRequest(), which copies across a fixed set of fields;
 * anything the request did not explicitly ask for - an SSN, a phone number, an
 * IP hash, a field some future form adds - is absent because it was never
 * copied, not because a filter recognised it. A deny-list would have to be
 * updated every time the intake form grows a field, and the failure mode of
 * forgetting is leaking PII to a third-party model.
 *
 * payload() is the only serialisation, so there is one place where "what the
 * model sees" is decided and one string for a test to assert against.
 *
 * © AI WebScapes 2026
 */
final class AIRequest
{
    /**
     * @param array<string, string> $fields
     */
    public function __construct(private array $fields)
    {
    }

    /**
     * @return array<string, string>
     */
    public function fields(): array
    {
        return $this->fields;
    }

    /**
     * The exact bytes that would leave this system.
     */
    public function payload(): string
    {
        $json = json_encode($this->fields, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        // Encoding failure must not fall through to a partially-encoded string:
        // an empty object sends nothing rather than risking sending anything.
        return $json === false ? '{}' : $json;
    }
}
