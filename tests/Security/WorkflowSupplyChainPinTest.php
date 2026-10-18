<?php

declare(strict_types=1);

namespace App\Tests\Security;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * SEC-007 supply-chain hardening — the CI workflow's own dependencies.
 *
 * WHY THIS TEST EXISTS
 * --------------------
 * `.github/workflows/ci.yml` is the required `quality-gate` status check on
 * `main`. It runs third-party actions, and every one of them was referenced by
 * a MUTABLE tag (`actions/checkout@v4`, `gitleaks/gitleaks-action@v2`, ...).
 * A tag is a pointer a maintainer - or anyone who compromises that maintainer's
 * account - can repoint at any commit. That makes a mutable tag an unverified
 * code path inside our gate, with our `GITHUB_TOKEN` in scope.
 *
 * GitHub's own hardening guidance is to pin to a full-length commit SHA, which
 * is immutable:
 *   https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
 * ("GitHub offers policies at the repository and organization level to require
 *  actions to be pinned to a full-length commit SHA.")
 *
 * This test enforces the shape mechanically so a future edit cannot quietly
 * reintroduce a floating tag.
 *
 * DELIBERATELY NOT ASSERTING EXACT SHAS
 * -------------------------------------
 * The SHAs themselves are chosen once and then maintained by Dependabot
 * (`.github/dependabot.yml`, github-actions ecosystem). Asserting a literal SHA
 * here would make every Dependabot bump fail the suite - turning the control
 * into an obstacle. So this test pins the *invariant* (full 40-hex SHA + a
 * version comment) and leaves the *value* to Dependabot. The one-time
 * correctness of the initial SHAs is verified against the GitHub API at
 * migration time, not re-asserted on every run.
 *
 * Dependency-free by design: the PHPUnit gate runs inside the app container and
 * on the CI runner, neither of which has a YAML library (no ext-yaml, no
 * symfony/yaml, no yq/python/node). Line parsing matches the existing repo
 * precedent in tests/Deploy/LocalInferenceComposeTest.php.
 *
 * © AI WebScapes 2026
 */
final class WorkflowSupplyChainPinTest extends TestCase
{
    private const WORKFLOW = __DIR__ . '/../../.github/workflows/ci.yml';
    private const DEPENDABOT = __DIR__ . '/../../.github/dependabot.yml';

    /**
     * The third-party actions the gate is expected to run. Kept as a set so a
     * newly introduced action must be consciously added here (and pinned).
     *
     * @var list<string>
     */
    private const EXPECTED_ACTIONS = [
        'actions/checkout',
        'shivammathur/setup-php',
        'actions/cache',
        'actions/upload-artifact',
        'gitleaks/gitleaks-action',
    ];

    #[Test]
    public function test_workflow_file_exists_and_is_readable(): void
    {
        self::assertFileExists(self::WORKFLOW, 'The required quality-gate workflow must exist.');
        self::assertIsString(
            file_get_contents(self::WORKFLOW),
            'The workflow must be readable so its pins can be audited.'
        );
    }

    /**
     * The core control: every `uses:` is `owner/repo@<40-hex-char SHA>`.
     * A mutable tag (`@v4`), a branch (`@main`), or a short SHA all fail.
     */
    #[Test]
    public function test_every_action_is_pinned_to_a_full_length_commit_sha(): void
    {
        $mutable = [];

        foreach ($this->usesLines() as $line) {
            $ref = $this->refOf($line);
            if ($ref === null) {
                continue;
            }

            if (preg_match('/^[0-9a-f]{40}$/', $ref) !== 1) {
                $mutable[] = sprintf('  %s   (ref "%s" is not a 40-char commit SHA)', trim($line), $ref);
            }
        }

        self::assertSame(
            [],
            $mutable,
            "A third-party action is referenced by a mutable ref. Pin it to the full-length "
            . "commit SHA for the release you intend, so the code cannot change under us:\n\n"
            . implode("\n", $mutable)
            . "\n\nA tag or branch is repointable; a full-length SHA is immutable. See the "
            . "GitHub secure-use reference (link in this class docblock)."
        );
    }

    /**
     * A bare SHA is unauditable - a reviewer cannot tell which release it is.
     * The pin carries its human-readable version as a trailing comment.
     */
    #[Test]
    public function test_every_pinned_action_carries_a_version_comment(): void
    {
        $unannotated = [];

        foreach ($this->usesLines() as $line) {
            $ref = $this->refOf($line);
            if ($ref === null || preg_match('/^[0-9a-f]{40}$/', $ref) !== 1) {
                continue;
            }

            // Expect a trailing `# v1.2.3` (optionally with a date) on the same line.
            if (preg_match('/#\s*v?\d+\.\d+\.\d+/', $line) !== 1) {
                $unannotated[] = '  ' . trim($line);
            }
        }

        self::assertSame(
            [],
            $unannotated,
            "A SHA-pinned action is missing its `# vX.Y.Z` version comment. Without it a "
            . "reviewer cannot tell which release the SHA is, and Dependabot's bump PR "
            . "cannot show a human-readable from/to:\n\n"
            . implode("\n", $unannotated)
        );
    }

    /**
     * Guards the expected set: if an action is added, removed, or renamed, the
     * change is deliberate and this list is updated with it.
     */
    #[Test]
    public function test_the_expected_actions_are_the_ones_referenced(): void
    {
        $actual = [];
        foreach ($this->usesLines() as $line) {
            $ref = $this->refOf($line);
            if ($ref === null) {
                continue;
            }
            $actual[] = $this->actionNameOf($line);
        }
        sort($actual);

        $expected = self::EXPECTED_ACTIONS;
        sort($expected);

        self::assertSame($expected, $actual, 'The workflow references an unexpected set of actions.');
    }

    /**
     * `ubuntu-latest` silently moves to a new Ubuntu when GitHub retags it,
     * changing the toolchain mid-project. Pin the image version.
     *
     * Comments are stripped first: this workflow deliberately explains WHY it
     * does not use `ubuntu-latest`, and a naive search would match that prose
     * and invert the verdict (a documented probe trap - the comment describing
     * the absence matches the search for the thing that must be absent).
     */
    #[Test]
    public function test_runner_image_is_version_pinned_not_latest(): void
    {
        $text = $this->codeOnly();

        self::assertStringNotContainsString(
            'ubuntu-latest',
            $text,
            '`runs-on: ubuntu-latest` is a moving target (GitHub retags it to a new Ubuntu '
            . 'release, which changes the toolchain without a commit). Pin the version, e.g. '
            . 'ubuntu-24.04.'
        );
        self::assertMatchesRegularExpression(
            '/runs-on:\s*ubuntu-\d{2}\.\d{2}/',
            $text,
            'A version-pinned Ubuntu runner image (e.g. ubuntu-24.04) must be declared.'
        );
    }

    /**
     * SHA pinning without an update mechanism freezes the actions forever.
     * Dependabot is the documented way to keep them current.
     */
    #[Test]
    public function test_dependabot_config_keeps_actions_current(): void
    {
        self::assertFileExists(
            self::DEPENDABOT,
            'SHA-pinned actions need an updater, or the pin becomes a freeze.'
        );

        $text = (string) file_get_contents(self::DEPENDABOT);

        self::assertMatchesRegularExpression(
            '/package-ecosystem:\s*["\']?github-actions["\']?/',
            $text,
            'dependabot.yml must monitor the github-actions ecosystem.'
        );
        self::assertMatchesRegularExpression(
            '/directory:\s*["\']?\/["\']?/',
            $text,
            'The github-actions ecosystem requires `directory: "/"` to find .github/workflows.'
        );
        self::assertMatchesRegularExpression(
            '/interval:\s*["\']?weekly["\']?/',
            $text,
            'The documented example schedules GitHub Actions updates weekly.'
        );
    }

    /**
     * The workflow with full-line comments removed, so an absence assertion
     * cannot be satisfied or defeated by explanatory prose. Only whole-line
     * comments are dropped; a trailing `# vX.Y.Z` pin annotation is preserved
     * because it is part of the `uses:` line other tests read.
     */
    private function codeOnly(): string
    {
        $text = (string) file_get_contents(self::WORKFLOW);
        $lines = preg_split('/\R/', $text);
        self::assertIsArray($lines);

        $kept = [];
        foreach ($lines as $line) {
            if (preg_match('/^\s*#/', $line) === 1) {
                continue;
            }
            $kept[] = $line;
        }

        return implode("\n", $kept);
    }

    /**
     * @return list<string> the raw `uses:` lines
     */
    private function usesLines(): array
    {
        $text = (string) file_get_contents(self::WORKFLOW);
        $lines = preg_split('/\R/', $text);
        self::assertIsArray($lines);

        $uses = [];
        foreach ($lines as $line) {
            // Only a real step directive: `- uses:` or `uses:` (allow `- uses:` inline).
            if (preg_match('/^\s*-?\s*uses:\s*\S+/', $line) === 1) {
                $uses[] = $line;
            }
        }

        return $uses;
    }

    /**
     * Extracts the ref after `@` from a `uses:` line, or null if it is a local
     * action (`./path`) which has no ref.
     */
    private function refOf(string $line): ?string
    {
        if (preg_match('/uses:\s*([^\s#]+)/', $line, $m) !== 1) {
            return null;
        }
        $target = $m[1];
        if (str_starts_with($target, './')) {
            return null;
        }
        $at = strrpos($target, '@');
        if ($at === false) {
            return null;
        }

        return substr($target, $at + 1);
    }

    private function actionNameOf(string $line): string
    {
        if (preg_match('/uses:\s*([^\s@#]+)@/', $line, $m) !== 1) {
            return '';
        }

        return $m[1];
    }
}
