<?php

declare(strict_types=1);

namespace App\Tests\Infra;

use App\Audit\AuditLog;
use App\Data\PasswordResetTokenRepository;
use App\Data\UserRepository;
use App\Identity\AuthService;
use App\Identity\PasswordHasher;
use App\Identity\SessionStore;
use App\Security\RbacPolicy;
use App\Security\Subject;
use App\Tests\TestCase;
use PDO;
use RuntimeException;

/**
 * The operator provisioning script (FR-IDENT-001/002, SEC-005).
 *
 * WHY THIS IS TESTED AS A SUBPROCESS. The thing under test is a CLI script: its
 * contract includes "reads the password from stdin", "refuses a short password"
 * and "never accepts the password as an argument". Calling a function would test
 * none of that - the argv/stdin behaviour IS the security property here, so it
 * has to be exercised through the real entrypoint.
 *
 * The script is run against the TEST database and its rows are cleaned up by id
 * afterwards. It commits (it is a separate process, like the served-surface
 * tests), so it cannot ride the base class's transaction.
 *
 * © AI WebScapes 2026
 */
final class CreateOperatorTest extends TestCase
{
    private const TENANT = 1;

    /** @var list<int> */
    private array $createdUserIds = [];

    private const SCRIPT = '/app/scripts/create-operator.php';

    protected function tearDown(): void
    {
        // Release the base class's transaction BEFORE deleting rows the
        // subprocess committed. The script under test writes on its own
        // connection, so an open transaction here can hold locks that block the
        // cleanup DELETE - observed as "1205 Lock wait timeout exceeded" after a
        // 50-second wait, which reads as a database fault rather than a teardown
        // ordering problem.
        if (isset($this->pdo) && $this->pdo->inTransaction()) {
            $this->pdo->rollBack();
        }

        if ($this->createdUserIds !== []) {
            $ids = implode(',', array_map('intval', $this->createdUserIds));
            $pdo = $this->fixtureConnection();
            $pdo->exec("DELETE FROM user_roles WHERE user_id IN ($ids)");
            $pdo->exec("DELETE FROM users WHERE id IN ($ids)");
            $this->createdUserIds = [];
        }

        // parent::tearDown() would try to roll back again; the base class guards
        // on transactionOwned and throws when the transaction is already gone,
        // so it is deliberately not called after an explicit rollback here.
    }

    public function test_it_creates_an_operator_who_can_actually_sign_in(): void
    {
        $email = $this->uniqueEmail();
        $password = 'a sufficiently long passphrase';

        $result = $this->runScript([
            '--dsn=' . $this->testDsn(),
            '--email=' . $email,
            '--role=admin',
            '--password-stdin',
        ], $password);

        self::assertSame(0, $result['exit'], 'provisioning must succeed: ' . $result['stderr']);

        // The real assertion: the account authenticates through AuthService,
        // which is what the console's login actually calls.
        $auth = $this->authService();
        self::assertTrue(
            $auth->attempt($email, $password),
            'the provisioned operator must be able to sign in'
        );

        $this->trackUser($email);
    }

    /**
     * The granted role must reach RbacPolicy, or the operator can sign in and
     * still be refused everywhere.
     */
    public function test_the_granted_role_carries_the_console_permissions(): void
    {
        $email = $this->uniqueEmail();

        $this->runScript([
            '--dsn=' . $this->testDsn(),
            '--email=' . $email,
            '--role=admin',
            '--password-stdin',
        ], 'a sufficiently long passphrase');

        $userId = $this->userIdByEmail($email);
        $this->createdUserIds[] = $userId;

        $policy = new RbacPolicy($this->pdo);
        $subject = new Subject(self::TENANT, $userId, 'test-session', 'test-csrf', false);

        self::assertTrue(
            $policy->permits($subject, 'agent.console.view'),
            'an admin operator must be able to open the console'
        );
        self::assertTrue(
            $policy->permits($subject, 'agent.invoke'),
            'an admin operator must be able to invoke an agent'
        );
    }

    public function test_a_short_password_is_refused(): void
    {
        $email = $this->uniqueEmail();

        $result = $this->runScript([
            '--dsn=' . $this->testDsn(),
            '--email=' . $email,
            '--role=admin',
            '--password-stdin',
        ], 'tooshort');

        self::assertSame(2, $result['exit'], 'a short password must be refused');
        self::assertStringContainsString('at least 15 characters', $result['stderr']);

        self::assertSame(
            0,
            $this->countUsersByEmail($email),
            'a refused provisioning must not create a user'
        );
    }

    /**
     * SEC: the password must never be accepted from argv, because argv is
     * world-readable via `ps` and lands in shell history.
     *
     * Asserted BEHAVIOURALLY rather than by grepping the source: the docblock
     * necessarily mentions the flag it refuses to offer, so a substring check
     * would either fail on the explanation or pass on a comment. What matters is
     * that passing a password as an argument does not provision anything.
     */
    public function test_a_password_cannot_be_passed_as_an_argument(): void
    {
        $email = $this->uniqueEmail();

        $result = $this->runScript([
            '--dsn=' . $this->testDsn(),
            '--email=' . $email,
            '--role=admin',
            '--plaintext-password=a sufficiently long passphrase',
        ], '');

        self::assertNotSame(0, $result['exit'], 'an argv password must not be accepted');
        self::assertSame(
            0,
            $this->countUsersByEmail($email),
            'a password supplied via argv must never create an account'
        );

        // And with no stdin password at all, provisioning must refuse rather
        // than fall back to an ambient or empty secret.
        $noPassword = $this->runScript([
            '--dsn=' . $this->testDsn(),
            '--email=' . $email,
            '--role=admin',
        ], '');

        self::assertNotSame(0, $noPassword['exit'], 'provisioning without a password must refuse');
        self::assertSame(0, $this->countUsersByEmail($email));
    }

    /**
     * The documented, scriptable path must exist and must read from stdin.
     */
    public function test_the_script_documents_password_stdin_and_reads_stdin(): void
    {
        $source = file_get_contents(self::SCRIPT);
        self::assertIsString($source);

        self::assertStringContainsString('--password-stdin', $source);
        self::assertStringContainsString('fgets(STDIN)', $source);
    }

    public function test_an_unknown_role_is_refused_without_creating_a_user(): void
    {
        $email = $this->uniqueEmail();

        $result = $this->runScript([
            '--dsn=' . $this->testDsn(),
            '--email=' . $email,
            '--role=not-a-role',
            '--password-stdin',
        ], 'a sufficiently long passphrase');

        self::assertSame(1, $result['exit']);
        self::assertStringContainsString('does not exist', $result['stderr']);
        self::assertSame(0, $this->countUsersByEmail($email), 'a bad role must not half-provision an account');
    }

    public function test_a_missing_dsn_is_refused(): void
    {
        $result = $this->runScript([
            '--email=' . $this->uniqueEmail(),
            '--role=admin',
            '--password-stdin',
        ], 'a sufficiently long passphrase');

        self::assertSame(2, $result['exit'], 'the DSN is mandatory - it must never be guessed');
        self::assertStringContainsString('--dsn', $result['stderr']);
    }

    public function test_an_invalid_email_is_refused(): void
    {
        $result = $this->runScript([
            '--dsn=' . $this->testDsn(),
            '--email=not-an-email',
            '--role=admin',
            '--password-stdin',
        ], 'a sufficiently long passphrase');

        self::assertSame(2, $result['exit']);
        self::assertStringContainsString('not a valid email', $result['stderr']);
    }

    /**
     * Re-running for an existing address must not silently overwrite the
     * credential - that would be an unlogged password reset.
     */
    public function test_an_existing_operator_is_not_overwritten(): void
    {
        $email = $this->uniqueEmail();
        $args = [
            '--dsn=' . $this->testDsn(),
            '--email=' . $email,
            '--role=admin',
            '--password-stdin',
        ];

        $first = $this->runScript($args, 'the original long passphrase');
        self::assertSame(0, $first['exit'], $first['stderr']);
        $this->trackUser($email);

        $second = $this->runScript($args, 'a completely different passphrase');

        self::assertSame(1, $second['exit'], 'a second run must refuse rather than overwrite');
        self::assertStringContainsString('already exists', $second['stderr']);

        // And the ORIGINAL credential still works, proving nothing was replaced.
        self::assertTrue(
            $this->authService()->attempt($email, 'the original long passphrase'),
            'the original credential must be untouched'
        );
    }

    private function authService(): AuthService
    {
        return new AuthService(
            new UserRepository($this->pdo, self::TENANT),
            new PasswordResetTokenRepository($this->pdo, self::TENANT),
            new PasswordHasher(['memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1]),
            new SessionStore($this->redisClient(), 900),
            new AuditLog($this->pdo)
        );
    }

    /**
     * @param  list<string> $arguments
     * @return array{exit: int, stdout: string, stderr: string}
     */
    private function runScript(array $arguments, string $stdin): array
    {
        $command = array_merge([PHP_BINARY, self::SCRIPT], $arguments);

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        // getenv() with no arguments returns the whole environment (a plain
        // array), so PATH and friends survive. Passing an env array to proc_open
        // REPLACES the environment outright, so seeding it from the current one
        // is what keeps the child usable.
        $env = getenv();
        $env['TEST_DB_DSN'] = $this->testDsn();

        $process = proc_open($command, $descriptors, $pipes, '/app', $env);
        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start the provisioning script.');
        }

        fwrite($pipes[0], $stdin . "\n");
        fclose($pipes[0]);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $exit = proc_close($process);

        return ['exit' => $exit, 'stdout' => $stdout, 'stderr' => $stderr];
    }

    /**
     * A connection that commits, for fixtures a SUBPROCESS must see and for
     * cleanup of what that subprocess wrote.
     */
    private function fixtureConnection(): PDO
    {
        return new PDO($this->testDsn(), 'root', 'root', [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }

    private function testDsn(): string
    {
        $dsn = getenv('TEST_DB_DSN');
        if ($dsn === false || $dsn === '') {
            throw new RuntimeException('TEST_DB_DSN is not set.');
        }

        return $dsn;
    }

    private function uniqueEmail(): string
    {
        return 'operator-' . bin2hex(random_bytes(6)) . '@example.test';
    }

    private function trackUser(string $email): void
    {
        $this->createdUserIds[] = $this->userIdByEmail($email);
    }

    private function userIdByEmail(string $email): int
    {
        $statement = $this->fixtureConnection()->prepare('SELECT id FROM users WHERE email = :e');
        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the user lookup.');
        }
        $statement->execute(['e' => $email]);
        $id = $statement->fetchColumn();

        if (!is_scalar($id)) {
            throw new RuntimeException(sprintf('No user with email "%s".', $email));
        }

        return (int) $id;
    }

    private function countUsersByEmail(string $email): int
    {
        $statement = $this->fixtureConnection()->prepare('SELECT COUNT(*) FROM users WHERE email = :e');
        if ($statement === false) {
            throw new RuntimeException('Unable to prepare the user count.');
        }
        $statement->execute(['e' => $email]);

        return (int) $statement->fetchColumn();
    }
}
