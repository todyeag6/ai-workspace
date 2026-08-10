<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Tenancy\TenantScope;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

/**
 * One deduplicated security finding (SFR-FIND-001) - an immutable value
 * object, never a live handle.
 *
 * WHAT SFR-FIND-001 ACTUALLY ASKS FOR
 * -----------------------------------
 * Thirteen facts per finding: unique fingerprint, title, category, severity,
 * confidence, affected assets, evidence, remediation, standards mapping,
 * owner, status, SLA and history. Every one is a field here (evidence and the
 * per-sighting part of history live in FindingOccurrence, which this object
 * points at through occurrenceCount/firstSeenAt/lastSeenAt), so a report
 * cannot quietly omit one and a caller cannot invent one.
 *
 * WHY THE AI'S OPINION IS A DIFFERENT FIELD FROM THE DECISION
 * -----------------------------------------------------------
 * SFR-AI-001 permits AI to summarize and suggest severity/remediation but
 * forbids it altering confirmed status, closing findings, or authorizing risk
 * acceptance without a human decision. BRD section 5 says the same thing from
 * the other side: "Automated severity is advisory until validated". So the
 * machine's severity and remediation are SEPARATE fields
 * (aiSuggestedSeverity / aiSuggestedRemediation) from the authoritative ones.
 * A reader can always tell which is which, and there is no field an AI can
 * write that IS the decision. withAiSuggestion() returns a new object that
 * changes only those advisory fields - it structurally cannot alter severity,
 * status, confidence or remediation, because it does not pass new values for
 * them.
 *
 * WHY A NEW SIGHTING RETURNS A NEW OBJECT (SFR-FIND-002)
 * ------------------------------------------------------
 * withOccurrence() returns a NEW Finding rather than mutating this one, for
 * the same reason Asset::bumpVersion() does: history that can be edited in
 * place is not history. firstSeenAt survives every sighting - a finding
 * observed again is not a new finding, and the record must keep saying when it
 * was first seen or "mean time to remediate" (BRD section 7) is unanswerable.
 *
 * NO CLOCK OF ITS OWN. Every moment is passed in by the caller, so the record
 * reflects the OBSERVED time rather than whenever this object happened to be
 * constructed - and every path stays deterministic under test.
 *
 * © AI WebScapes 2026
 */
final class Finding
{
    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    // -----------------------------------------------------------------
    // Severity (BRD section 5). Ordered least to most severe.
    // -----------------------------------------------------------------

    public const SEVERITY_INFORMATIONAL = 'informational';
    public const SEVERITY_LOW = 'low';
    public const SEVERITY_MEDIUM = 'medium';
    public const SEVERITY_HIGH = 'high';
    public const SEVERITY_CRITICAL = 'critical';

    /** @var list<string> */
    public const SEVERITIES = [
        self::SEVERITY_INFORMATIONAL,
        self::SEVERITY_LOW,
        self::SEVERITY_MEDIUM,
        self::SEVERITY_HIGH,
        self::SEVERITY_CRITICAL,
    ];

    // -----------------------------------------------------------------
    // Evidence confidence (BRD section 5 lists it as a severity input).
    // Deliberately NOT the suspected/confirmed axis - that is the status.
    // -----------------------------------------------------------------

    public const CONFIDENCE_LOW = 'low';
    public const CONFIDENCE_MEDIUM = 'medium';
    public const CONFIDENCE_HIGH = 'high';

    /** @var list<string> */
    public const CONFIDENCES = [
        self::CONFIDENCE_LOW,
        self::CONFIDENCE_MEDIUM,
        self::CONFIDENCE_HIGH,
    ];

    // -----------------------------------------------------------------
    // Status. The vocabulary SFR-REPORT-001 requires a report to be able to
    // distinguish: confirmed, suspected, informational, accepted, remediated
    // and not-retested items.
    // -----------------------------------------------------------------

    /** Observed, not yet validated by a human. The birth state. */
    public const STATUS_OPEN = 'open';

    /** A human has validated that the finding is real (SFR-AI-001). */
    public const STATUS_CONFIRMED = 'confirmed';

    /** A human reviewed it and judged it not a real finding (SBR-5.2). */
    public const STATUS_FALSE_POSITIVE = 'false_positive';

    /** A human accepted the risk (SBR-5.3, SFR-AI-001). */
    public const STATUS_RISK_ACCEPTED = 'risk_accepted';

    /** Fixed, and the fix has passing retest evidence (SFR-RETEST-001). */
    public const STATUS_REMEDIATED = 'remediated';

    /** Closed. Terminal. */
    public const STATUS_CLOSED = 'closed';

    /** @var list<string> */
    public const STATUSES = [
        self::STATUS_OPEN,
        self::STATUS_CONFIRMED,
        self::STATUS_FALSE_POSITIVE,
        self::STATUS_RISK_ACCEPTED,
        self::STATUS_REMEDIATED,
        self::STATUS_CLOSED,
    ];

    /**
     * The statuses SFR-AI-001 reserves for a human decision. Reaching any of
     * these without a named human is refused by FindingRepository - this list
     * is the single place that set is written down.
     *
     * @var list<string>
     */
    public const HUMAN_ONLY_STATUSES = [
        self::STATUS_CONFIRMED,
        self::STATUS_FALSE_POSITIVE,
        self::STATUS_RISK_ACCEPTED,
        self::STATUS_REMEDIATED,
        self::STATUS_CLOSED,
    ];

    // -----------------------------------------------------------------
    // Scan categories - FRD section 5, verbatim coverage list.
    // -----------------------------------------------------------------

    public const CATEGORY_TRANSPORT_EXPOSURE = 'transport-and-exposure';
    public const CATEGORY_HTTP_CONFIGURATION = 'http-configuration';
    public const CATEGORY_CONTENT_EXPOSURE = 'content-exposure';
    public const CATEGORY_AUTHENTICATION_SESSION = 'authentication-session';
    public const CATEGORY_AUTHORIZATION_API = 'authorization-api';
    public const CATEGORY_INPUT_HANDLING = 'input-handling';
    public const CATEGORY_DEPENDENCIES = 'dependencies';
    public const CATEGORY_AI_SECURITY = 'ai-security';
    public const CATEGORY_OPERATIONAL_CONTROLS = 'operational-controls';

    /** @var list<string> */
    public const CATEGORIES = [
        self::CATEGORY_TRANSPORT_EXPOSURE,
        self::CATEGORY_HTTP_CONFIGURATION,
        self::CATEGORY_CONTENT_EXPOSURE,
        self::CATEGORY_AUTHENTICATION_SESSION,
        self::CATEGORY_AUTHORIZATION_API,
        self::CATEGORY_INPUT_HANDLING,
        self::CATEGORY_DEPENDENCIES,
        self::CATEGORY_AI_SECURITY,
        self::CATEGORY_OPERATIONAL_CONTROLS,
    ];

    /**
     * @param list<int>    $affectedAssets   security_assets ids this finding touches.
     * @param list<string> $standardsMapping Standard references (ASVS/API/GenAI/NIST ids).
     */
    public function __construct(
        private readonly int $tenantId,
        private readonly int $id,
        private readonly string $fingerprint,
        private readonly string $title,
        private readonly string $category,
        private readonly string $severity,
        private readonly string $confidence,
        private readonly array $affectedAssets,
        private readonly ?string $remediation,
        private readonly array $standardsMapping,
        private readonly string $owner,
        private readonly string $status,
        private readonly ?DateTimeImmutable $slaDueAt,
        private readonly DateTimeImmutable $firstSeenAt,
        private readonly DateTimeImmutable $lastSeenAt,
        private readonly int $occurrenceCount,
        private readonly ?string $aiSuggestedSeverity = null,
        private readonly ?string $aiSuggestedRemediation = null,
        private readonly ?string $aiSummary = null,
        private readonly ?string $confirmedBy = null,
        private readonly ?DateTimeImmutable $confirmedAt = null,
        private readonly ?string $closedBy = null,
        private readonly ?DateTimeImmutable $closedAt = null,
    ) {
        // A finding outside a real tenant is not one anyone may read (AC-001),
        // so it cannot be constructed at all. fromRow() puts the value through
        // TenantScope first, which refuses null as well.
        if ($tenantId <= 0) {
            throw new InvalidArgumentException(
                'A finding must belong to a real tenant; 0 or negative is not a tenant (AC-001).'
            );
        }

        if (trim($fingerprint) === '') {
            throw new InvalidArgumentException('A finding must carry a unique fingerprint (SFR-FIND-001).');
        }

        if (trim($title) === '') {
            throw new InvalidArgumentException('A finding must carry a title (SFR-FIND-001).');
        }

        // The vocabularies are allowlists, not denylists (AC-002): an
        // unrecognised severity is refused rather than stored and guessed at
        // later, because the safe interpretation of an unknown severity is not
        // obviously "low".
        self::assertOneOf($category, self::CATEGORIES, 'category');
        self::assertOneOf($severity, self::SEVERITIES, 'severity');
        self::assertOneOf($confidence, self::CONFIDENCES, 'confidence');
        self::assertOneOf($status, self::STATUSES, 'status');

        if ($aiSuggestedSeverity !== null) {
            self::assertOneOf($aiSuggestedSeverity, self::SEVERITIES, 'ai_suggested_severity');
        }

        if ($occurrenceCount < 1) {
            throw new InvalidArgumentException(
                'A finding exists because it was observed, so it has at least one occurrence.'
            );
        }

        foreach ($affectedAssets as $assetId) {
            if ($assetId <= 0) {
                throw new InvalidArgumentException('An affected asset id must be positive.');
            }
        }

        foreach ($standardsMapping as $standard) {
            if (trim($standard) === '') {
                throw new InvalidArgumentException('A standards mapping entry must be a non-empty string.');
            }
        }

        if ($lastSeenAt < $firstSeenAt) {
            // A sighting before the first sighting is a contradiction, and
            // silently accepting it would corrupt every age/SLA calculation.
            throw new InvalidArgumentException(
                'A finding cannot last be seen before it was first seen (SFR-FIND-002).'
            );
        }
    }

    /**
     * Builds the object from one database row.
     *
     * @param array<string, scalar|null> $row
     */
    public static function fromRow(array $row): self
    {
        // Throws for null / 0 / negative before anything else is read.
        $tenant = new TenantScope(self::intOrNull($row['tenant_id'] ?? null));

        $id = self::intOrNull($row['id'] ?? null);
        if ($id === null || $id <= 0) {
            throw new InvalidArgumentException('A finding row must carry a positive id.');
        }

        return new self(
            $tenant->id(),
            $id,
            self::stringOf($row['fingerprint'] ?? null),
            self::stringOf($row['title'] ?? null),
            self::stringOf($row['category'] ?? null, self::CATEGORY_OPERATIONAL_CONTROLS),
            self::stringOf($row['severity'] ?? null, self::SEVERITY_INFORMATIONAL),
            self::stringOf($row['confidence'] ?? null, self::CONFIDENCE_MEDIUM),
            self::decodeIntList($row['affected_assets'] ?? null),
            self::stringOrNull($row['remediation'] ?? null),
            self::decodeStringList($row['standards_mapping'] ?? null),
            self::stringOf($row['owner'] ?? null, ''),
            self::stringOf($row['status'] ?? null, self::STATUS_OPEN),
            self::timeOrNull($row['sla_due_at'] ?? null),
            self::timeOf($row['first_seen_at'] ?? null, 'first_seen_at'),
            self::timeOf($row['last_seen_at'] ?? null, 'last_seen_at'),
            max(1, self::intOf($row['occurrence_count'] ?? null)),
            self::stringOrNull($row['ai_suggested_severity'] ?? null),
            self::stringOrNull($row['ai_suggested_remediation'] ?? null),
            self::stringOrNull($row['ai_summary'] ?? null),
            self::stringOrNull($row['confirmed_by'] ?? null),
            self::timeOrNull($row['confirmed_at'] ?? null),
            self::stringOrNull($row['closed_by'] ?? null),
            self::timeOrNull($row['closed_at'] ?? null),
        );
    }

    /**
     * The same finding, observed again (SFR-FIND-002).
     *
     * firstSeenAt is carried over untouched and the occurrence count rises;
     * NOTHING about the human decision - status, severity, owner, confirmation
     * - is touched, because re-observing an issue is not a review of it. A
     * finding a human accepted the risk on stays accepted when it is seen
     * again; the sighting is recorded, the disposition is not overwritten.
     *
     * @param list<int> $newlyAffectedAssets Assets this sighting adds, if any.
     */
    public function withOccurrence(DateTimeImmutable $observedAt, array $newlyAffectedAssets = []): self
    {
        $assets = $this->affectedAssets;
        foreach ($newlyAffectedAssets as $assetId) {
            if (!in_array($assetId, $assets, true)) {
                $assets[] = $assetId;
            }
        }

        return new self(
            $this->tenantId,
            $this->id,
            $this->fingerprint,
            $this->title,
            $this->category,
            $this->severity,
            $this->confidence,
            $assets,
            $this->remediation,
            $this->standardsMapping,
            $this->owner,
            $this->status,
            $this->slaDueAt,
            // History does not move.
            $this->firstSeenAt,
            // A sighting older than the last one does not rewind the clock.
            $observedAt > $this->lastSeenAt ? $observedAt : $this->lastSeenAt,
            $this->occurrenceCount + 1,
            $this->aiSuggestedSeverity,
            $this->aiSuggestedRemediation,
            $this->aiSummary,
            $this->confirmedBy,
            $this->confirmedAt,
            $this->closedBy,
            $this->closedAt,
        );
    }

    /**
     * The same finding carrying an AI's ADVISORY opinion (SFR-AI-001).
     *
     * Note what this method cannot do: it takes no status, no owner, no
     * authoritative severity and no authoritative remediation, so there is no
     * argument by which an AI-driven caller could alter the decision. That is
     * the requirement made structural rather than checked - BRD section 5's
     * "automated severity is advisory until validated" holds by construction.
     */
    public function withAiSuggestion(
        ?string $suggestedSeverity = null,
        ?string $suggestedRemediation = null,
        ?string $summary = null
    ): self {
        if ($suggestedSeverity !== null) {
            self::assertOneOf($suggestedSeverity, self::SEVERITIES, 'ai_suggested_severity');
        }

        return new self(
            $this->tenantId,
            $this->id,
            $this->fingerprint,
            $this->title,
            $this->category,
            // Untouched, deliberately: the authoritative severity is a human's.
            $this->severity,
            $this->confidence,
            $this->affectedAssets,
            $this->remediation,
            $this->standardsMapping,
            $this->owner,
            $this->status,
            $this->slaDueAt,
            $this->firstSeenAt,
            $this->lastSeenAt,
            $this->occurrenceCount,
            $suggestedSeverity ?? $this->aiSuggestedSeverity,
            $suggestedRemediation ?? $this->aiSuggestedRemediation,
            $summary ?? $this->aiSummary,
            $this->confirmedBy,
            $this->confirmedAt,
            $this->closedBy,
            $this->closedAt,
        );
    }

    public function tenantId(): int
    {
        return $this->tenantId;
    }

    public function id(): int
    {
        return $this->id;
    }

    public function fingerprint(): string
    {
        return $this->fingerprint;
    }

    public function title(): string
    {
        return $this->title;
    }

    public function category(): string
    {
        return $this->category;
    }

    public function severity(): string
    {
        return $this->severity;
    }

    public function confidence(): string
    {
        return $this->confidence;
    }

    /**
     * @return list<int>
     */
    public function affectedAssets(): array
    {
        return $this->affectedAssets;
    }

    public function remediation(): ?string
    {
        return $this->remediation;
    }

    /**
     * @return list<string>
     */
    public function standardsMapping(): array
    {
        return $this->standardsMapping;
    }

    public function owner(): string
    {
        return $this->owner;
    }

    public function status(): string
    {
        return $this->status;
    }

    public function slaDueAt(): ?DateTimeImmutable
    {
        return $this->slaDueAt;
    }

    public function firstSeenAt(): DateTimeImmutable
    {
        return $this->firstSeenAt;
    }

    public function lastSeenAt(): DateTimeImmutable
    {
        return $this->lastSeenAt;
    }

    public function occurrenceCount(): int
    {
        return $this->occurrenceCount;
    }

    public function aiSuggestedSeverity(): ?string
    {
        return $this->aiSuggestedSeverity;
    }

    public function aiSuggestedRemediation(): ?string
    {
        return $this->aiSuggestedRemediation;
    }

    public function aiSummary(): ?string
    {
        return $this->aiSummary;
    }

    public function confirmedBy(): ?string
    {
        return $this->confirmedBy;
    }

    public function confirmedAt(): ?DateTimeImmutable
    {
        return $this->confirmedAt;
    }

    public function closedBy(): ?string
    {
        return $this->closedBy;
    }

    public function closedAt(): ?DateTimeImmutable
    {
        return $this->closedAt;
    }

    /**
     * True once a human has validated the finding (SFR-AI-001). Asked as a
     * question rather than compared as a string so a typo cannot silently
     * report an unconfirmed finding as confirmed.
     */
    public function isConfirmed(): bool
    {
        return $this->status === self::STATUS_CONFIRMED;
    }

    /**
     * True for a status only a human may set. FindingRepository consults this
     * before every transition.
     */
    public function isHumanDecided(): bool
    {
        return in_array($this->status, self::HUMAN_ONLY_STATUSES, true);
    }

    /**
     * Whether the remediation deadline has passed at the given moment. Null
     * SLA (informational findings) is never overdue.
     */
    public function isOverdue(DateTimeImmutable $now): bool
    {
        return $this->slaDueAt !== null && $now > $this->slaDueAt;
    }

    /**
     * The sanctioned projection for a report: every fact SFR-FIND-001 names,
     * in one place, with the AI's advisory opinion clearly labelled as such
     * and no live handles in it.
     *
     * @return array{
     *     tenant_id: int,
     *     id: int,
     *     fingerprint: string,
     *     title: string,
     *     category: string,
     *     severity: string,
     *     confidence: string,
     *     affected_assets: list<int>,
     *     remediation: string|null,
     *     standards_mapping: list<string>,
     *     owner: string,
     *     status: string,
     *     sla_due_at: string|null,
     *     first_seen_at: string,
     *     last_seen_at: string,
     *     occurrence_count: int,
     *     ai_suggested_severity: string|null,
     *     ai_suggested_remediation: string|null,
     *     ai_summary: string|null,
     *     confirmed_by: string|null,
     *     confirmed_at: string|null,
     *     closed_by: string|null,
     *     closed_at: string|null
     * }
     */
    public function toReportArray(): array
    {
        return [
            'tenant_id' => $this->tenantId,
            'id' => $this->id,
            'fingerprint' => $this->fingerprint,
            'title' => $this->title,
            'category' => $this->category,
            'severity' => $this->severity,
            'confidence' => $this->confidence,
            'affected_assets' => $this->affectedAssets,
            'remediation' => $this->remediation,
            'standards_mapping' => $this->standardsMapping,
            'owner' => $this->owner,
            'status' => $this->status,
            'sla_due_at' => $this->slaDueAt?->format(self::TIMESTAMP_FORMAT),
            'first_seen_at' => $this->firstSeenAt->format(self::TIMESTAMP_FORMAT),
            'last_seen_at' => $this->lastSeenAt->format(self::TIMESTAMP_FORMAT),
            'occurrence_count' => $this->occurrenceCount,
            'ai_suggested_severity' => $this->aiSuggestedSeverity,
            'ai_suggested_remediation' => $this->aiSuggestedRemediation,
            'ai_summary' => $this->aiSummary,
            'confirmed_by' => $this->confirmedBy,
            'confirmed_at' => $this->confirmedAt?->format(self::TIMESTAMP_FORMAT),
            'closed_by' => $this->closedBy,
            'closed_at' => $this->closedAt?->format(self::TIMESTAMP_FORMAT),
        ];
    }

    /**
     * @param list<string> $allowed
     */
    private static function assertOneOf(string $value, array $allowed, string $field): void
    {
        if (!in_array($value, $allowed, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown finding %s "%s". It must be one of: %s (allowlist, AC-002).',
                $field,
                $value,
                implode(', ', $allowed)
            ));
        }
    }

    private static function intOrNull(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }

        return is_scalar($value) ? (int) $value : null;
    }

    private static function intOf(mixed $value): int
    {
        return is_scalar($value) ? (int) $value : 0;
    }

    private static function stringOf(mixed $value, string $default = ''): string
    {
        if ($value === null || !is_scalar($value)) {
            return $default;
        }

        $string = (string) $value;

        return $string === '' ? $default : $string;
    }

    private static function stringOrNull(mixed $value): ?string
    {
        if ($value === null || !is_scalar($value)) {
            return null;
        }

        $string = (string) $value;

        return $string === '' ? null : $string;
    }

    /**
     * A stored timestamp is read back as UTC, matching the way the repository
     * writes it. A value the database cannot have produced is refused rather
     * than coerced to "now", which would silently reset a finding's history.
     */
    private static function timeOf(mixed $value, string $field): DateTimeImmutable
    {
        if (!is_scalar($value) || (string) $value === '') {
            throw new InvalidArgumentException(sprintf('A finding row must carry %s.', $field));
        }

        $parsed = DateTimeImmutable::createFromFormat(
            self::TIMESTAMP_FORMAT,
            (string) $value,
            new DateTimeZone('UTC')
        );

        if ($parsed === false) {
            throw new InvalidArgumentException(sprintf(
                'Unreadable finding timestamp "%s" for %s; expected %s in UTC.',
                (string) $value,
                $field,
                self::TIMESTAMP_FORMAT
            ));
        }

        return $parsed;
    }

    private static function timeOrNull(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || !is_scalar($value) || (string) $value === '') {
            return null;
        }

        $parsed = DateTimeImmutable::createFromFormat(
            self::TIMESTAMP_FORMAT,
            (string) $value,
            new DateTimeZone('UTC')
        );

        return $parsed === false ? null : $parsed;
    }

    /**
     * @return list<int>
     */
    private static function decodeIntList(mixed $value): array
    {
        $ids = [];
        foreach (self::decodeList($value) as $entry) {
            if (is_int($entry) || (is_string($entry) && ctype_digit($entry))) {
                $id = (int) $entry;
                if ($id > 0 && !in_array($id, $ids, true)) {
                    $ids[] = $id;
                }
            }
        }

        return $ids;
    }

    /**
     * @return list<string>
     */
    private static function decodeStringList(mixed $value): array
    {
        $items = [];
        foreach (self::decodeList($value) as $entry) {
            if (is_string($entry) && trim($entry) !== '' && !in_array($entry, $items, true)) {
                $items[] = $entry;
            }
        }

        return $items;
    }

    /**
     * @return list<mixed>
     */
    private static function decodeList(mixed $value): array
    {
        if (!is_string($value) || trim($value) === '') {
            return [];
        }

        $decoded = json_decode($value, true);

        return is_array($decoded) ? array_values($decoded) : [];
    }
}
