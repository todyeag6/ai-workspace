<?php

declare(strict_types=1);

namespace Aiwebscapes\PhpStan;

use PDO;
use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\Type\ObjectType;

/**
 * Forbids raw PDO::query() / PDO::exec() outside App\Data\TenantRepository.
 *
 * WHY THIS EXISTS AT ALL
 * ----------------------
 * The plan is explicit that tenancy is the linchpin and must be enforced
 * "with a PHPStan rule, not discipline". TenantRepository makes the SCOPED
 * path easy, but it cannot stop anyone reaching around it: one
 * `$pdo->query("SELECT * FROM client_contacts")` in a controller silently
 * defeats FR-TEN-002 and AC-001 for that code path, and it will look
 * completely ordinary in review. query() and exec() are precisely the two PDO
 * methods that take finished SQL and support no bound parameters, so a tenant
 * value in them is necessarily interpolated - unscoped-query surface and
 * injection surface at once.
 *
 * WHY IT FLAGS EVERY RAW CALL, NOT ONLY ONES NAMING A KNOWN CLIENT TABLE
 * ---------------------------------------------------------------------
 * Matching a hard-coded table list would make the rule fail OPEN: every new
 * client table added after this commit would escape it until someone
 * remembered to update the list, which is exactly the discipline the rule is
 * supposed to replace. So the default answer is no, and the table list is used
 * only to sharpen the message when a known client table is literally named.
 * Three cases, three identifiers:
 *
 *   1. unscopedClientQuery - literal SQL naming a known tenant-scoped table.
 *      The flagship violation.
 *   2. rawPdoQuery         - literal SQL naming none of them. Still refused:
 *      the table list is not the security boundary, TenantRepository is.
 *   3. opaqueSqlQuery      - the SQL is not a compile-time constant, so the
 *      rule cannot see the table at all. Refused fail-closed, which also
 *      closes the obvious bypass of concatenating the table name in.
 *
 * WHAT IS DELIBERATELY EXCLUDED, AND WHY
 * --------------------------------------
 * Excluding paths is what keeps this rule honest rather than trivially
 * satisfiable, so each exclusion is a considered decision, not a convenience:
 *
 *   - tests/    The harness in tests/TestCase.php has to APPLY MIGRATIONS
 *               (DDL, which no scoped repository can or should express) and
 *               tests/Tenancy/TenantScopeTest.php has to seed rows for tenants
 *               it is not scoped to - that is the entire cross-tenant proof.
 *               A test that could only reach data through the thing it is
 *               testing could not falsify it. Tests are not a client-data
 *               access path; they are the evidence for one.
 *   - scripts/  migrate.php, backup.php and restore.php operate on the whole
 *               database - schema and all tenants at once. "Scope this backup
 *               to one tenant" is not a coherent request.
 *   - build/    This rule's own tooling.
 *   - legacy/ and vendor/  Not ours to change; already outside phpcs too.
 *
 * Note what is NOT excluded: src/ in its entirety, including every controller,
 * service and future repository. That is where the rule has to bite.
 *
 * KNOWN LIMIT (stated rather than hidden): prepare() is not covered, because
 * prepare() is the sanctioned path - it is how TenantRepository itself binds
 * :tenant. A determined author can still prepare() an unscoped statement in
 * src/. Closing that needs SQL-level analysis of the query text, which is
 * P1-T4's audit-trail territory; this rule closes the surface the plan named.
 *
 * © AI WebScapes 2026
 *
 * @implements Rule<MethodCall>
 */
final class NoUnscopedClientQueryRule implements Rule
{
    /**
     * The only class allowed to hold raw PDO query/exec calls. Subclasses
     * inherit the permission - they are scoped by construction.
     */
    private const REPOSITORY_BASE = 'App\Data\TenantRepository';

    /**
     * The two PDO methods that accept finished SQL and cannot bind parameters.
     */
    private const FORBIDDEN_METHODS = ['query', 'exec'];

    /**
     * Tables carrying a tenant_id column (migrations/001_tenants_identity.sql),
     * plus tables the plan will add later. Used ONLY to produce a sharper
     * message - see the class docblock on why it is not the gate.
     *
     * `leads` is listed ahead of its migration (P1-T10) on purpose: the rule
     * should already be right about it on the day that table appears.
     *
     * @var list<string>
     */
    private const CLIENT_TABLES = [
        'users',
        'roles',
        'user_roles',
        'client_contacts',
        'leads',
        'agents',
        'agent_versions',
    ];

    /**
     * Path fragments whose files may use raw PDO. Matched against the
     * forward-slash-normalised absolute file path, with surrounding slashes,
     * so `/app/tests/Tenancy/X.php` matches `/tests/` but a hypothetical
     * `src/Attests/X.php` does not.
     *
     * @var list<string>
     */
    private const EXCLUDED_PATH_FRAGMENTS = [
        '/tests/',
        '/scripts/',
        '/build/',
        '/legacy/',
        '/vendor/',
    ];

    public function getNodeType(): string
    {
        return MethodCall::class;
    }

    /**
     * @return list<\PHPStan\Rules\IdentifierRuleError>
     */
    public function processNode(Node $node, Scope $scope): array
    {
        if (!$node->name instanceof Identifier) {
            // A dynamic method name ($pdo->$method(...)). Out of scope: the
            // rule would have to guess, and guessing produces false positives
            // that get the whole rule disabled.
            return [];
        }

        $method = strtolower($node->name->toString());
        if (!in_array($method, self::FORBIDDEN_METHODS, true)) {
            return [];
        }

        // Only PDO. PDOStatement::execute(), Redis, Twig and anything else
        // that happens to have a query()/exec() method are none of our business.
        if (!(new ObjectType(PDO::class))->isSuperTypeOf($scope->getType($node->var))->yes()) {
            return [];
        }

        if ($this->isExcludedFile($scope->getFile())) {
            return [];
        }

        $classReflection = $scope->getClassReflection();
        if ($classReflection !== null && $classReflection->getName() === self::REPOSITORY_BASE) {
            // Only the base class App\Data\TenantRepository is exempt. It has no
            // raw query()/exec() of its own (it prepares and binds in run(), and
            // $pdo is private so a subclass cannot reach it either). A SUBCLASS
            // is deliberately NOT exempt: a LeadRepository that opened its own
            // raw PDO call would be exactly the bypass this rule exists to stop,
            // and ClassReflection::is() would have wrongly widened the exemption
            // to every subclass. Match the exact name, not instanceof.
            return [];
        }

        return [$this->buildError($method, $this->literalSql($node, $scope))];
    }

    /**
     * The SQL argument if - and only if - it is a single compile-time constant
     * string. Anything else (concatenation, variable, sprintf) returns null and
     * is treated as unanalysable.
     */
    private function literalSql(MethodCall $node, Scope $scope): ?string
    {
        $args = $node->getArgs();
        if ($args === []) {
            return null;
        }

        $constantStrings = $scope->getType($args[0]->value)->getConstantStrings();
        if (count($constantStrings) !== 1) {
            return null;
        }

        return $constantStrings[0]->getValue();
    }

    /**
     * @return \PHPStan\Rules\IdentifierRuleError
     */
    private function buildError(string $method, ?string $sql): object
    {
        $remedy = sprintf(
            'Extend App\Data\TenantRepository and use selectScoped()/updateScoped()/'
            . 'deleteScoped(), which force `tenant_id = :tenant` into the statement and '
            . 'bind it internally, or use PDO::prepare() with explicit bindings if this '
            . 'genuinely touches no client data.'
        );

        if ($sql === null) {
            return RuleErrorBuilder::message(sprintf(
                'PDO::%s() is called with SQL that is not a compile-time constant, so '
                . 'tenant scoping cannot be verified here. Refused fail-closed '
                . '(FR-TEN-002). %s',
                $method,
                $remedy
            ))->identifier('aiwebscapes.opaqueSqlQuery')->build();
        }

        $table = $this->clientTableIn($sql);
        if ($table !== null) {
            return RuleErrorBuilder::message(sprintf(
                'PDO::%s() reaches the tenant-scoped table "%s" outside %s. This bypasses '
                . 'mandatory tenant scoping (FR-TEN-002) and makes a cross-tenant read '
                . 'possible (AC-001). %s',
                $method,
                $table,
                self::REPOSITORY_BASE,
                $remedy
            ))->identifier('aiwebscapes.unscopedClientQuery')->build();
        }

        return RuleErrorBuilder::message(sprintf(
            'PDO::%s() executes unparameterised SQL outside %s. Raw query/exec is refused '
            . 'everywhere in src/, not only for today\'s client tables, so that a client '
            . 'table added tomorrow is covered without anyone remembering to update a '
            . 'list (FR-TEN-002). %s',
            $method,
            self::REPOSITORY_BASE,
            $remedy
        ))->identifier('aiwebscapes.rawPdoQuery')->build();
    }

    /**
     * The first known client table named in $sql, matched on word boundaries so
     * that `roles` does not match inside `user_roles` by accident, and checked
     * longest-name-first so `user_roles` wins over `roles` when both appear.
     */
    private function clientTableIn(string $sql): ?string
    {
        $tables = self::CLIENT_TABLES;
        usort($tables, static fn(string $a, string $b): int => strlen($b) <=> strlen($a));

        foreach ($tables as $table) {
            if (preg_match('/\b' . preg_quote($table, '/') . '\b/i', $sql) === 1) {
                return $table;
            }
        }

        return null;
    }

    private function isExcludedFile(string $file): bool
    {
        $normalised = str_replace('\\', '/', $file);

        foreach (self::EXCLUDED_PATH_FRAGMENTS as $fragment) {
            if (str_contains($normalised, $fragment)) {
                return true;
            }
        }

        return false;
    }
}
