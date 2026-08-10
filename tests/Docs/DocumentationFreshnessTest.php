<?php

declare(strict_types=1);

namespace App\Tests\Docs;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase as Base;

/**
 * Keeps documentation from drifting out of sync with the repository.
 *
 * WHY THIS TEST EXISTS
 * --------------------
 * Hand-maintained status prose in docs/ went stale every single time. The old
 * docs/HANDOFF.md described the repo as "Phase 0 -> Phase 1" with "161 tests"
 * while Phase 3 was shipping; docs/SESSION_HANDOFF_P1T14.md announced work as
 * "NOT YET PUSHED" that had been on origin/main for days. Sessions then opened
 * by reading those files and repeating the numbers back as fact.
 *
 * The fix was to derive state from git (scripts/status.sh) instead of writing
 * it down. But a fix that relies on nobody ever re-adding a status table is
 * not a fix - it is a hope. So this test enforces the rule mechanically: if a
 * doc starts carrying a hardcoded commit hash, a test count, or a
 * pushed/unpushed claim, the suite goes red and names the file.
 *
 * This does NOT extend to the Base class from App\Tests: it needs no database,
 * so it stays a plain PHPUnit test and runs in milliseconds.
 *
 * © AI WebScapes 2026
 */
final class DocumentationFreshnessTest extends Base
{
    /**
     * Patterns that indicate a document is asserting mutable repository state.
     *
     * Each is paired with the reason, so a failure explains itself rather than
     * just naming a regex.
     *
     * @var array<string, string>
     */
    private const FORBIDDEN = [
        // "NOT YET PUSHED", "not yet pushed to origin", "0 unpushed commits"
        '/\b(not yet pushed|unpushed commit|is unpushed|are unpushed)\b/i' =>
            'a push claim goes stale the moment someone pushes; run scripts/status.sh instead',

        // "161 tests", "OK (346 tests, 1183 assertions)"
        '/\b\d{2,}\s+tests?\b(?!\s*\/\s*directory)/i' =>
            'a hardcoded test count goes stale on the next commit; run the suite instead',

        '/\b\d{3,}\s+assertions?\b/i' =>
            'a hardcoded assertion count goes stale on the next commit; run the suite instead',

        // "HEAD = 8e339f9", "commit 01c7c91", "as of `5db4f0f`"
        '/\b(HEAD|commit|hash)\b[^.\n]{0,20}\b[0-9a-f]{7,40}\b/i' =>
            'a pinned commit hash goes stale on the next commit; git log is the record',
    ];

    /**
     * Documents allowed to reference specific commits, because their subject
     * IS a historical event rather than current state.
     *
     * @var list<string>
     */
    private const HISTORICAL = [
        'CI_AND_BRANCH_PROTECTION.md', // cites the commit that fixed the CI service label
        'TRACEABILITY.md',             // maps requirements to the commits implementing them
    ];

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function documentProvider(): iterable
    {
        $dir = dirname(__DIR__, 2) . '/docs';
        $files = glob($dir . '/*.md');

        if ($files === false) {
            return;
        }

        foreach ($files as $file) {
            $name = basename($file);
            if (in_array($name, self::HISTORICAL, true)) {
                continue;
            }

            yield $name => [$name, $file];
        }
    }

    #[DataProvider('documentProvider')]
    public function test_documentation_does_not_hardcode_mutable_repository_state(
        string $name,
        string $path
    ): void {
        $contents = file_get_contents($path);
        self::assertIsString($contents, sprintf('Could not read docs/%s.', $name));

        // Prose that merely EXPLAINS the rule (as HANDOFF.md does, at length)
        // must not trip it. Only lines that read as an assertion of state are
        // checked, so a sentence inside a fenced block or a quote is exempt.
        $lines = preg_split('/\R/', $contents);
        self::assertIsArray($lines);

        $inFence = false;
        $offenders = [];

        foreach ($lines as $number => $line) {
            if (preg_match('/^\s*```/', $line) === 1) {
                $inFence = !$inFence;
                continue;
            }

            if ($inFence || preg_match('/^\s*>/', $line) === 1) {
                continue;
            }

            foreach (self::FORBIDDEN as $pattern => $why) {
                if (preg_match($pattern, $line) === 1) {
                    $offenders[] = sprintf('  docs/%s:%d — %s', $name, $number + 1, $why);
                    $offenders[] = sprintf('      %s', trim($line));
                }
            }
        }

        self::assertSame(
            [],
            $offenders,
            sprintf(
                "docs/%s asserts mutable repository state.\n\n%s\n\n"
                . "State belongs in `bash scripts/status.sh`, which derives it from git at run "
                . "time. Written-down state has gone stale every time it has been tried here, "
                . "and stale docs have caused wrong status reports to the owner.",
                $name,
                implode("\n", $offenders)
            )
        );
    }

    public function test_the_status_script_exists_and_is_the_documented_entry_point(): void
    {
        $root = dirname(__DIR__, 2);

        self::assertFileExists(
            $root . '/scripts/status.sh',
            'scripts/status.sh is what docs/HANDOFF.md points at instead of written state.'
        );

        $handoff = file_get_contents($root . '/docs/HANDOFF.md');
        self::assertIsString($handoff);
        self::assertStringContainsString(
            'scripts/status.sh',
            $handoff,
            'docs/HANDOFF.md must direct the reader to the derived status script.'
        );
    }
}
