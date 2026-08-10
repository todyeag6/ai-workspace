<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use DateTimeImmutable;
use DateTimeZone;
use RuntimeException;

/**
 * One machine-readable result from one scanner adapter (SFR-SCAN-002,
 * SFR-SCAN-003) - an immutable value object.
 *
 * WHY THIS IS A TYPED OBJECT AND NOT A STRING
 * -------------------------------------------
 * SFR-SCAN-002 requires adapters to produce MACHINE-READABLE results. A tool's
 * stdout is not machine-readable in any useful sense: turning it into findings
 * needs a regex, and a regex over unstructured text is exactly how "connection
 * refused" becomes evidence of a vulnerability. Everything downstream reads
 * fields here, so there is no text-scraping step to get wrong.
 *
 * WHY A FAILURE IS A STATUS AND NOT A FINDING
 * -------------------------------------------
 * SFR-SCAN-003 is unambiguous: tool failure shall not be interpreted as target
 * vulnerability, and the failure state and its evidence shall be recorded. The
 * status allowlist therefore separates the two vocabularies - `finding` says
 * something about the TARGET, while `error`, `timeout` and `refused` say
 * something about the RUN - and a status outside the allowlist is refused at
 * construction rather than passed along to be guessed at. failure() is the only
 * convenient way to build a failed result, and it cannot produce a finding.
 *
 * NO DATABASE, NO CLOCK ON THE DECISION PATH. Persisting a result is somebody
 * else's job (the evidence store); this object is what gets handed over.
 *
 * © AI WebScapes 2026
 */
final class ScannerResult
{
    /** The run completed and found nothing worth reporting. */
    public const STATUS_OK = 'ok';

    /** Informational output about the target - not a vulnerability claim. */
    public const STATUS_INFO = 'info';

    /** A claim ABOUT THE TARGET. Only ever produced from a successful run. */
    public const STATUS_FINDING = 'finding';

    /** The TOOL failed. Says nothing about the target (SFR-SCAN-003). */
    public const STATUS_ERROR = 'error';

    /** The tool ran out of its allotted time. Also not a target claim. */
    public const STATUS_TIMEOUT = 'timeout';

    /** The adapter declined to run at all - untrusted or disabled. */
    public const STATUS_REFUSED = 'refused';

    /**
     * The complete vocabulary. Anything else is a defect to surface, not a
     * value to store: an unknown status downstream would have to be guessed
     * at, and the safe guess is not obviously "not a finding".
     */
    private const STATUSES = [
        self::STATUS_OK,
        self::STATUS_INFO,
        self::STATUS_FINDING,
        self::STATUS_ERROR,
        self::STATUS_TIMEOUT,
        self::STATUS_REFUSED,
    ];

    /** The statuses that describe a failed or declined RUN, not a target. */
    private const FAILURE_STATUSES = [
        self::STATUS_ERROR,
        self::STATUS_TIMEOUT,
        self::STATUS_REFUSED,
    ];

    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    /** Recorded in UTC so results from different workers are comparable. */
    public readonly string $recordedAt;

    /**
     * @param array<string, mixed> $data The structured payload. Empty for a failure.
     */
    public function __construct(
        public readonly string $scanner,
        public readonly string $target,
        public readonly string $status,
        public readonly array $data,
        public readonly ?string $errorMessage = null,
        public readonly int $exitCode = 0,
        ?DateTimeImmutable $recordedAt = null,
    ) {
        if (trim($scanner) === '') {
            throw new RuntimeException('A scanner result must name the scanner that produced it.');
        }

        if (trim($target) === '') {
            throw new RuntimeException('A scanner result must name the target it describes.');
        }

        if (!in_array($status, self::STATUSES, true)) {
            throw new RuntimeException(sprintf(
                'Unknown scanner result status "%s". A result must be one of: %s (SFR-SCAN-003).',
                $status,
                implode(', ', self::STATUSES)
            ));
        }

        $this->recordedAt = ($recordedAt ?? new DateTimeImmutable('now', new DateTimeZone('UTC')))
            ->format(self::TIMESTAMP_FORMAT);
    }

    /**
     * The recorded failure of a TOOL (SFR-SCAN-003).
     *
     * There is deliberately no $status argument: this factory cannot be talked
     * into producing a finding, and the message plus exit code are carried so
     * the failure has evidence rather than being an empty absence of results.
     */
    public static function failure(
        string $scanner,
        string $target,
        string $errorMessage,
        int $exitCode = 1,
        ?DateTimeImmutable $recordedAt = null
    ): self {
        return new self(
            $scanner,
            $target,
            self::STATUS_ERROR,
            [],
            $errorMessage === '' ? 'The scanner failed without reporting a reason.' : $errorMessage,
            $exitCode,
            $recordedAt
        );
    }

    /**
     * The adapter declined to run (SFR-SELF-002). Not a failure of the target
     * and not a failure of the tool - the run never happened.
     */
    public static function refused(
        string $scanner,
        string $target,
        string $reason,
        ?DateTimeImmutable $recordedAt = null
    ): self {
        return new self($scanner, $target, self::STATUS_REFUSED, [], $reason, 0, $recordedAt);
    }

    /**
     * True ONLY for a claim about the target. Callers that build reports ask
     * this rather than comparing strings, so a failure cannot be mistaken for
     * a vulnerability by a typo.
     */
    public function isFinding(): bool
    {
        return $this->status === self::STATUS_FINDING;
    }

    public function isFailure(): bool
    {
        return in_array($this->status, self::FAILURE_STATUSES, true);
    }

    /**
     * The machine-readable shape (SFR-SCAN-002): fixed keys, typed values, no
     * free text to parse except the human-facing error message.
     *
     * @return array{
     *     scanner: string,
     *     target: string,
     *     status: string,
     *     data: array<string, mixed>,
     *     error_message: string|null,
     *     exit_code: int,
     *     recorded_at: string
     * }
     */
    public function toMachineArray(): array
    {
        return [
            'scanner' => $this->scanner,
            'target' => $this->target,
            'status' => $this->status,
            'data' => $this->data,
            'error_message' => $this->errorMessage,
            'exit_code' => $this->exitCode,
            'recorded_at' => $this->recordedAt,
        ];
    }
}
