<?php

declare(strict_types=1);

/**
 * Provisions an operator who can sign in to the agent console.
 *
 *   php scripts/create-operator.php --dsn='mysql:host=db;dbname=aiwebscapes;charset=utf8mb4' \
 *       --email=ops@example.com --role=admin --password-stdin
 *
 * WHY THIS EXISTS. The platform shipped with NO user seeded anywhere: `INSERT
 * IGNORE INTO users` appears in zero migrations, so the console's login had
 * nothing to authenticate against. A migration is the wrong home for a
 * credential (it would put a password hash in version control and make the
 * account appear in every environment, including test), so provisioning is an
 * operator action with an explicit DSN.
 *
 * --dsn IS MANDATORY AND HAS NO DEFAULT, matching scripts/migrate.php. Reading
 * DB_DSN from the environment would mean running this in the wrong shell
 * silently creates an account on the production database.
 *
 * THE PASSWORD NEVER ARRIVES AS AN ARGUMENT. --password-stdin (or an
 * interactive prompt) is the only way in. An argv flag is world-readable via
 * `ps` on a shared host, and it also lands in shell history - so a credential
 * passed that way is disclosed to any local process before this script even
 * starts. This is the one place the platform accepts a plaintext secret, so it
 * is the one place that discipline matters most.
 *
 * NIST SP 800-63B-4 (current revision, superseding SP 800-63B) requires a
 * password used as a single factor to be at least 15 characters, forbids
 * composition rules, and recommends screening against known-compromised values
 * rather than mandating rotation. The length floor is enforced here; a full
 * blocklist is deliberately not implemented rather than half-implemented.
 * https://pages.nist.gov/800-63-4/sp800-63b/authenticators/
 *
 * © AI WebScapes 2026
 */

require __DIR__ . '/../vendor/autoload.php';

use App\Data\GrantRepository;
use App\Data\UserRepository;
use App\Identity\PasswordHasher;
use App\Infra\CliOptions;

const USAGE = <<<TXT
Usage: php scripts/create-operator.php --dsn=<pdo-mysql-dsn> --email=<address>
                                       [--role=<code>] [--password-stdin]
                                       [--user=<user>] [--password=<password>]

  --dsn             REQUIRED. e.g. 'mysql:host=db;dbname=aiwebscapes;charset=utf8mb4'
                    There is no default: this script never guesses which
                    database to create an account on.
  --email           REQUIRED. The operator's address.
  --role            Role code to grant. Defaults to 'admin'.
                    Must already exist for the tenant (see migration 002).
  --tenant          Tenant id. Defaults to 1.
  --password-stdin  Read the password from stdin. PREFERRED.
  --user            DB user. Defaults to \$DB_USER, then 'root'.
  --password        DB password. Defaults to \$DB_PASSWORD, then 'root'.

  There is deliberately NO --plaintext-password flag: an argv password is
  visible to every local process via ps, and lands in shell history.
TXT;

/**
 * The minimum length NIST SP 800-63B-4 requires for a single-factor password.
 * A passphrase is expected, not a short complex string.
 */
const MIN_PASSWORD_LENGTH = 15;

/**
 * @param list<string> $argv
 */
function main(array $argv): int
{
    try {
        $options = CliOptions::fromArgv(array_slice($argv, 1));
    } catch (InvalidArgumentException $e) {
        fwrite(STDERR, $e->getMessage() . "\n\n" . USAGE . "\n");

        return 2;
    }

    if ($options->has('help')) {
        fwrite(STDOUT, USAGE . "\n");

        return 0;
    }

    try {
        $dsn = $options->requireValue('dsn');
        $email = $options->requireValue('email');
    } catch (InvalidArgumentException $e) {
        fwrite(STDERR, $e->getMessage() . "\n\n" . USAGE . "\n");

        return 2;
    }

    $tenantId = (int) ($options->value('tenant') ?? '1');
    if ($tenantId <= 0) {
        fwrite(STDERR, "--tenant must be a positive integer.\n");

        return 2;
    }

    $roleCode = $options->value('role') ?? 'admin';

    $password = readPassword($options);
    if ($password === null) {
        return 2;
    }

    if (strlen($password) < MIN_PASSWORD_LENGTH) {
        fwrite(STDERR, sprintf(
            "The password must be at least %d characters (NIST SP 800-63B-4 requires this for a "
            . "single-factor credential). Got %d. Use a passphrase.\n",
            MIN_PASSWORD_LENGTH,
            strlen($password)
        ));

        return 2;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        fwrite(STDERR, sprintf('"%s" is not a valid email address.' . "\n", $email));

        return 2;
    }

    try {
        $pdo = new PDO($dsn, $options->valueOrEnv('user', 'DB_USER', 'root'), $options->valueOrEnv('password', 'DB_PASSWORD', 'root'), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    } catch (Throwable $e) {
        fwrite(STDERR, 'Database connection failed: ' . $e->getMessage() . "\n");

        return 1;
    }

    // The role must exist for this tenant BEFORE the user is created, so a typo
    // fails without leaving a half-provisioned account behind.
    $roleId = roleId($pdo, $tenantId, $roleCode);
    if ($roleId === null) {
        fwrite(STDERR, sprintf(
            "Role \"%s\" does not exist for tenant %d. Create it first (see migrations/002_authz_audit.sql).\n",
            $roleCode,
            $tenantId
        ));

        return 1;
    }

    $users = new UserRepository($pdo, $tenantId);
    $existing = $users->findByEmail($email);

    if ($existing !== null) {
        fwrite(STDERR, sprintf(
            "A user with that address already exists for tenant %d (id %d). "
            . "Refusing to overwrite a credential; remove the account first if that is intended.\n",
            $tenantId,
            $existing->id()
        ));

        return 1;
    }

    $hasher = new PasswordHasher();
    $hash = $hasher->hash($password);

    // The user row and its role grant are one unit of work: a user without a
    // role can sign in and then be refused everywhere, which is the hardest
    // state to diagnose. Both writes commit together or neither does.
    $pdo->beginTransaction();

    try {
        $statement = $pdo->prepare(
            'INSERT INTO users (tenant_id, email, password_hash, role, is_active, status, mfa_secret)'
            . ' VALUES (:tenant_id, :email, :password_hash, :role, 1, :status, NULL)'
        );
        if ($statement === false) {
            fwrite(STDERR, "Unable to prepare the user insert.\n");

            return 1;
        }

        $statement->execute([
            'tenant_id' => $tenantId,
            'email' => $email,
            'password_hash' => $hash,
            // The legacy users.role column is a display/label field;
            // authorisation reads user_roles -> role_permissions (see
            // RbacPolicy). Kept in step with the granted role so the two do not
            // contradict each other.
            'role' => in_array($roleCode, ['admin', 'manager', 'viewer'], true) ? $roleCode : 'viewer',
            'status' => 'active',
        ]);

        $userId = (int) $pdo->lastInsertId();

        $grant = $pdo->prepare(
            'INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES (:t, :u, :r)'
        );
        if ($grant === false) {
            fwrite(STDERR, "Unable to prepare the role grant.\n");

            return 1;
        }
        $grant->execute(['t' => $tenantId, 'u' => $userId, 'r' => $roleId]);

        $pdo->commit();
    } catch (Throwable $e) {
        // A database refusal is an operator-facing message, not a stack trace.
        // The transaction is rolled back so a failure here cannot leave a user
        // with no role - which would be an account that can sign in and be
        // refused everywhere, the hardest kind to diagnose.
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        fwrite(STDERR, 'Provisioning failed: ' . $e->getMessage() . "\n");

        return 1;
    }

    fwrite(STDOUT, sprintf(
        "Created operator %s (id %d) in tenant %d with role \"%s\".\n",
        $email,
        $userId,
        $tenantId,
        $roleCode
    ));

    return 0;
}

/**
 * Reads the password without ever accepting it from argv.
 *
 * --password-stdin is the documented path (scriptable, no tty needed). Without
 * it, the password is prompted for on the terminal with echo disabled, so it
 * does not appear on screen or in a scrollback buffer.
 *
 * @return string|null Null when no usable password was supplied.
 */
function readPassword(CliOptions $options): ?string
{
    if ($options->has('password-stdin')) {
        $line = fgets(STDIN);
        if ($line === false) {
            fwrite(STDERR, "--password-stdin was given but stdin was empty.\n");

            return null;
        }

        // Strip only the line terminator - trailing spaces are legitimate in a
        // passphrase and must not be silently altered.
        $password = rtrim($line, "\r\n");

        if ($password === '') {
            fwrite(STDERR, "The password read from stdin was empty.\n");

            return null;
        }

        return $password;
    }

    if (!function_exists('shell_exec') || !stream_isatty(STDIN)) {
        fwrite(STDERR, "No password supplied. Pass --password-stdin and pipe it in.\n");

        return null;
    }

    fwrite(STDOUT, 'Password: ');
    shell_exec('stty -echo 2>/dev/null');
    $line = fgets(STDIN);
    shell_exec('stty echo 2>/dev/null');
    fwrite(STDOUT, "\n");

    if ($line === false) {
        return null;
    }

    $password = rtrim($line, "\r\n");

    return $password === '' ? null : $password;
}

/**
 * Resolves a role code to its id for a tenant, or null when it does not exist.
 *
 * Uses a JOIN against `roles` so the answer is "this tenant has a role with
 * this code" rather than "some row exists" - and it is called BEFORE any write,
 * so an unknown role is a clean refusal rather than a foreign-key violation
 * three frames down. (An FK violation here is not a hypothetical: it is exactly
 * what surfaced while testing this script, as an uncaught PDOException and a
 * bare exit 255 that read like a crash rather than a validation error.)
 */
function roleId(PDO $pdo, int $tenantId, string $roleCode): ?int
{
    $statement = $pdo->prepare(
        'SELECT r.id FROM roles r WHERE r.tenant_id = :t AND r.code = :c LIMIT 1'
    );
    if ($statement === false) {
        return null;
    }

    $statement->execute(['t' => $tenantId, 'c' => $roleCode]);
    $id = $statement->fetchColumn();

    if (!is_scalar($id)) {
        return null;
    }

    // Confirm the id is really visible for this tenant. A scalar from the driver
    // is not proof the row exists (a driver can hand back a string for a
    // no-row query in some configurations), and the FK below would otherwise
    // fail ungracefully.
    $exists = $pdo->prepare('SELECT COUNT(*) FROM roles WHERE id = :id AND tenant_id = :t');
    if ($exists === false) {
        return null;
    }
    $exists->execute(['id' => (int) $id, 't' => $tenantId]);

    return (int) $exists->fetchColumn() === 1 ? (int) $id : null;
}

exit(main($argv));
