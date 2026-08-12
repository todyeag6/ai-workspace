<?php

declare(strict_types=1);

namespace App\Tests\Deploy;

use App\Deploy\ReleaseRecord;
use App\Tests\TestCase;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;

/**
 * FR-DEP-002 - every release carries a unique version, change record, test
 * evidence, security status, migration status and rollback reference. The
 * ReleaseRecord value object enforces all six fields and refuses a malformed
 * one (fail-closed on release metadata).
 */
final class ReleaseRecordTest extends TestCase
{
    /**
     * @return array<string, string>
     */
    private function valid(): array
    {
        return [
            'version' => '1.4.0',
            'change_record' => 'Tighten lead dashboard tenant scoping.',
            'test_evidence' => 'phpunit green on iso DB; 1423 assertions.',
            'security_status' => 'pen-test SEC-009 passed; 0 critical.',
            'migration_status' => '021 applied; rollback-to-020 verified.',
            'rollback_reference' => 'git tag v1.4.0-rc1',
        ];
    }

    #[Test]
    public function test_from_array_requires_all_six_fields(): void
    {
        $data = $this->valid();
        unset($data['rollback_reference']);

        $this->expectException(InvalidArgumentException::class);
        ReleaseRecord::fromArray($data);
    }

    #[Test]
    public function test_from_array_refuses_empty_value(): void
    {
        $data = $this->valid();
        $data['change_record'] = '   ';

        $this->expectException(InvalidArgumentException::class);
        ReleaseRecord::fromArray($data);
    }

    #[Test]
    public function test_version_must_look_like_a_release(): void
    {
        $data = $this->valid();
        $data['version'] = 'latest';

        $this->expectException(InvalidArgumentException::class);
        ReleaseRecord::fromArray($data);
    }

    #[Test]
    public function test_accepts_well_formed_version(): void
    {
        $data = $this->valid();
        $data['version'] = 'v2.0.1-rc3';

        $record = ReleaseRecord::fromArray($data);
        self::assertSame('v2.0.1-rc3', $record->version);
    }

    #[Test]
    public function test_to_array_round_trips(): void
    {
        $data = $this->valid();
        $record = ReleaseRecord::fromArray($data);

        self::assertSame($data, $record->toArray());
    }

    #[Test]
    public function test_extra_fields_are_rejected(): void
    {
        $data = $this->valid();
        $data['surprise'] = 'x';

        $this->expectException(InvalidArgumentException::class);
        ReleaseRecord::fromArray($data);
    }
}
