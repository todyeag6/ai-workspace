<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use App\Data\TenantRepository;
use DateTimeImmutable;
use InvalidArgumentException;

/**
 * The tenant-scoped, append-only comment thread on a remediation (FRD section
 * 2 lists "comments" among the Remediation Tracker's responsibilities).
 *
 * WHY APPEND-ONLY. Same reasoning as finding_occurrences and retests: a
 * comment is a record of what somebody said at the moment a decision was
 * taken. A thread that can be edited afterwards is not evidence of the
 * discussion, and this thread sits directly beside decisions about whether a
 * security finding gets fixed or waived.
 *
 * WHY THE BODY IS LENGTH-CAPPED. The cap comes from the ratifiable
 * config/security/REMEDIATION_POLICY.php, not from a constant here. Comments
 * are rendered into client reports, and an unbounded blob in a report is both
 * a denial-of-service surface and a place to hide content. The reporting layer
 * escapes on output; this is the size half of the same defence.
 *
 * © AI WebScapes 2026
 */
final class RemediationCommentRepository extends TenantRepository
{
    private const TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    protected function table(): string
    {
        return 'remediation_comments';
    }

    /**
     * @return list<string>
     */
    protected function columns(): array
    {
        return [
            'id',
            'tenant_id',
            'remediation_id',
            'finding_id',
            'author',
            'body',
            'created_at',
        ];
    }

    /**
     * Appends one comment. The ONLY write path this class offers.
     */
    public function add(
        int $remediationId,
        int $findingId,
        string $author,
        string $body,
        DateTimeImmutable $postedAt,
        int $maxChars
    ): int {
        $who = trim($author);
        if ($who === '') {
            // An anonymous comment on a security decision is not a record of
            // anything (SFR-AUD-001).
            throw new InvalidArgumentException('A remediation comment must name its author.');
        }

        $text = trim($body);
        if ($text === '') {
            throw new InvalidArgumentException('A remediation comment must have a body.');
        }

        return (int) $this->insertScoped([
            'remediation_id' => $remediationId,
            'finding_id' => $findingId,
            'author' => $who,
            'body' => mb_substr($text, 0, $maxChars),
            'created_at' => $postedAt->format(self::TIMESTAMP_FORMAT),
        ]);
    }

    /**
     * The thread on one remediation, oldest first.
     *
     * @return list<array{
     *     id: int,
     *     remediation_id: int,
     *     finding_id: int,
     *     author: string,
     *     body: string,
     *     created_at: string
     * }>
     */
    public function forRemediation(int $remediationId): array
    {
        $rows = $this->selectScoped(
            'remediation_id = :remediation_id',
            ['remediation_id' => $remediationId]
        );

        $comments = [];
        foreach ($rows as $row) {
            $comments[] = [
                'id' => (int) ($row['id'] ?? 0),
                'remediation_id' => (int) ($row['remediation_id'] ?? 0),
                'finding_id' => (int) ($row['finding_id'] ?? 0),
                'author' => (string) ($row['author'] ?? ''),
                'body' => (string) ($row['body'] ?? ''),
                'created_at' => (string) ($row['created_at'] ?? ''),
            ];
        }

        // Sorted in PHP: selectScoped() parenthesises the predicate, so an
        // ORDER BY inside it would be invalid SQL.
        usort($comments, static fn (array $a, array $b): int => $a['id'] <=> $b['id']);

        return $comments;
    }

    /**
     * How many comments one remediation carries.
     */
    public function countForRemediation(int $remediationId): int
    {
        return count($this->selectScoped(
            'remediation_id = :remediation_id',
            ['remediation_id' => $remediationId]
        ));
    }
}
