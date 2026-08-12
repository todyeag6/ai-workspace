<?php

declare(strict_types=1);

namespace App\Deploy;

use InvalidArgumentException;

/**
 * FR-DEP-002 - every release carries a unique version, change record, test
 * evidence, security status, migration status and rollback reference.
 *
 * Pure value object: it enforces the six mandatory fields and refuses a
 * malformed release record (fail-closed on release metadata) but performs no
 * I/O. The release pipeline (scripts/deploy-client.php, CI) builds one of these
 * from the actual artifacts so a release cannot ship without all six present.
 *
 * © AI WebScapes 2026
 */
final class ReleaseRecord
{
    /**
     * The six mandatory fields, in canonical order.
     *
     * @var list<string>
     */
    private const REQUIRED = [
        'version',
        'change_record',
        'test_evidence',
        'security_status',
        'migration_status',
        'rollback_reference',
    ];

    /**
     * A release version: a semantic version (1.4.0) optionally "v"-prefixed and
     * with a pre-release tag (v2.0.1-rc3). Anything else is refused.
     */
    private const VERSION_PATTERN = '/^v?\d+\.\d+\.\d+(-(rc|alpha|beta)\d*)?$/';

    /**
     * @param array<string, string> $data exactly REQUIRED keys, each non-empty.
     */
    public static function fromArray(array $data): self
    {
        foreach (self::REQUIRED as $field) {
            if (!array_key_exists($field, $data)) {
                throw new InvalidArgumentException(sprintf('ReleaseRecord missing required field "%s".', $field));
            }
            $value = $data[$field];
            if (trim($value) === '') {
                throw new InvalidArgumentException(sprintf('ReleaseRecord field "%s" must be a non-empty string.', $field));
            }
        }

        foreach (array_keys($data) as $key) {
            if (!in_array($key, self::REQUIRED, true)) {
                throw new InvalidArgumentException(sprintf('ReleaseRecord has unexpected field "%s".', $key));
            }
        }

        if (preg_match(self::VERSION_PATTERN, $data['version']) !== 1) {
            throw new InvalidArgumentException(sprintf('ReleaseRecord version "%s" is not a valid release version.', $data['version']));
        }

        return new self(
            $data['version'],
            $data['change_record'],
            $data['test_evidence'],
            $data['security_status'],
            $data['migration_status'],
            $data['rollback_reference']
        );
    }

    public function __construct(
        public readonly string $version,
        public readonly string $changeRecord,
        public readonly string $testEvidence,
        public readonly string $securityStatus,
        public readonly string $migrationStatus,
        public readonly string $rollbackReference
    ) {
    }

    /**
     * @return array<string, string> the six fields, keyed by their canonical name.
     */
    public function toArray(): array
    {
        return [
            'version' => $this->version,
            'change_record' => $this->changeRecord,
            'test_evidence' => $this->testEvidence,
            'security_status' => $this->securityStatus,
            'migration_status' => $this->migrationStatus,
            'rollback_reference' => $this->rollbackReference,
        ];
    }
}
