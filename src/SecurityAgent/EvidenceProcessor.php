<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use JsonException;
use RuntimeException;

/**
 * Builds a store-ready Evidence item from a raw scanner result, enforcing
 * SFR-EVID-001 (completeness + hash) and SFR-EVID-002 (redaction before
 * display/storage).
 *
 * WHY THIS COMPONENT DECIDES AND NEVER PERSISTS. The EvidenceRepository only
 * moves rows; the decision about whether a given piece of raw output is safe
 * and complete enough to become evidence lives here. That is the same
 * decide-not-act split ScopeManager / SafetyMonitor use in this module: the
 * judge holds no socket. process() returns a fully-formed Evidence value
 * object; whether it gets stored is somebody else's call.
 *
 * WHY THE PROCESSOR FAILS CLOSED ON UNREDACTED SECRETS. SFR-EVID-002 requires
 * secrets, session identifiers, personal data and unnecessary response bodies
 * to be redacted BEFORE routine display - and "before storage" is the strict
 * reading, because evidence that is stored with a secret in it is redacted
 * never, not redacted-later. So process() scans the raw content, and if it
 * finds sensitive kinds it REDACTS them and records the kinds; it never returns
 * an Evidence object that still carries the secret. A caller that asks for
 * "no redaction" against sensitive content gets a refusal, not a silently
 * unredacted row (SFR-EVID-002, SFR-SELF-004).
 *
 * WHY THE HASH IS COMPUTED HERE FROM A CANONICALIZED CONTENT. SFR-EVID-001
 * requires a cryptographic hash "where stored as artifact". The hash must be
 * over a DETERMINISTIC form of the content (sorted keys, redacted values) so
 * the same observation produces the same digest every time - which is what
 * makes the hash useful for tamper-evidence and for the SFR-FIND-002
 * deduplication that P3-T4's finding engine will perform against it. The
 * processor owns that canonicalization because it owns the content decision.
 *
 * NO DATABASE. This component is pure: given the same inputs it returns the
 * same Evidence, which is what makes every path - redact, refuse, hash,
 * fingerprint - provable without a scanner, a tenant, or a socket.
 *
 * © AI WebScapes 2026
 */
final class EvidenceProcessor
{
    private const HASH_ALGO = 'sha256';

    /**
     * Builds an Evidence item from a raw scanner result.
     *
     * @param array<string, mixed> $responseMetadata What the target returned.
     * @param array<string, mixed>|null $reproduction The re-runnable recipe.
     * @param array<string, mixed> $extraContent Extra content to scan for
     *        secrets (e.g. raw response body, headers). Merged into the scanned
     *        surface but NOT persisted unless explicitly included above.
     *
     * @throws EvidenceRedactionRequired When the content carries sensitive
     *         data and $allowRedaction is false - the fail-closed path.
     */
    public function process(
        int $tenantId,
        int $scanId,
        ?int $assetId,
        ScannerResult $result,
        string $scannerVersion,
        string $requestCategory,
        array $responseMetadata,
        ?array $reproduction = null,
        ?DateTimeImmutable $capturedAt = null,
        bool $allowRedaction = true,
        array $extraContent = []
    ): Evidence {
        if ($tenantId <= 0) {
            throw new InvalidArgumentException('Evidence must belong to a real tenant (AC-001).');
        }
        if ($scanId <= 0) {
            throw new InvalidArgumentException('Evidence must reference a positive scan id.');
        }
        if (trim($result->scanner) === '') {
            throw new InvalidArgumentException('Evidence must name the scanner (SFR-EVID-001).');
        }
        if (trim($scannerVersion) === '') {
            throw new InvalidArgumentException('Evidence must name the scanner version (SFR-EVID-001, SFR-SELF-002).');
        }
        if (trim($result->target) === '') {
            throw new InvalidArgumentException('Evidence must name the target (SFR-EVID-001).');
        }
        if (trim($requestCategory) === '') {
            throw new InvalidArgumentException('Evidence must carry a request category (SFR-EVID-001).');
        }

        // The surface we scan for secrets is the union of what we will persist
        // plus anything the caller flagged as sensitive-but-auxiliary.
        $scanned = array_merge($responseMetadata, $extraContent);
        $kinds = (new RedactionScanner())->scan($scanned);

        if ($kinds !== [] && !$allowRedaction) {
            // Fail closed: do not hand back an Evidence object that still holds
            // a secret. The caller must either permit redaction or not store.
            throw new EvidenceRedactionRequired(
                $kinds,
                'Evidence contains sensitive material and redaction was not permitted (SFR-EVID-002).'
            );
        }

        $storedMetadata = $responseMetadata;
        $redactedAt = null;
        if ($kinds !== []) {
            // Redaction happens, and only then is the item safe to persist.
            $storedMetadata = (new RedactionScanner())->redact($responseMetadata);
            $redactedAt = ($capturedAt ?? new DateTimeImmutable('now', new DateTimeZone('UTC')));
        }

        $hash = $this->contentHash(
            $result->scanner,
            $scannerVersion,
            $result->target,
            $requestCategory,
            $storedMetadata,
            $reproduction
        );

        return new Evidence(
            $tenantId,
            0, // assigned by the repository on store()
            $scanId,
            $assetId,
            $result->scanner,
            $scannerVersion,
            $result->target,
            $capturedAt ?? new DateTimeImmutable('now', new DateTimeZone('UTC')),
            $requestCategory,
            $storedMetadata,
            $reproduction,
            $hash,
            $redactedAt,
            $kinds === [] ? null : $kinds
        );
    }

    /**
     * The canonical content hash. Deterministic: keys sorted, redacted values
     * used (so the digest tracks the SAFE form, not the secret), scanner +
     * version + target + category included so the same observation under a
     * different tool produces a different hash.
     *
     * @param array<string, mixed> $responseMetadata
     * @param array<string, mixed>|null $reproduction
     */
    public function contentHash(
        string $scanner,
        string $scannerVersion,
        string $target,
        string $requestCategory,
        array $responseMetadata,
        ?array $reproduction
    ): string {
        $canonical = [
            'scanner' => $scanner,
            'scanner_version' => $scannerVersion,
            'target' => $target,
            'request_category' => $requestCategory,
            'response_metadata' => $this->canonicalize($responseMetadata),
            'reproduction' => $reproduction === null ? null : $this->canonicalize($reproduction),
        ];

        try {
            $json = json_encode($canonical, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Could not canonicalize evidence for hashing.', 0, $e);
        }

        return hash(self::HASH_ALGO, $json);
    }

    /**
     * Recursively canonicalizes mixed content into a stable, key-sorted form
     * so identical observations always hash identically.
     *
     * @param mixed $value
     * @return mixed
     */
    private function canonicalize(mixed $value): mixed
    {
        if (is_array($value)) {
            $out = [];
            // Sort by key so key order never influences the hash.
            $keys = array_keys($value);
            sort($keys);
            foreach ($keys as $key) {
                $out[$key] = $this->canonicalize($value[$key]);
            }

            return $out;
        }

        return $value;
    }
}
