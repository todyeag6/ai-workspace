<?php

declare(strict_types=1);

namespace App\Data;

use App\Tenancy\TenantScope;
use InvalidArgumentException;
use PDO;
use PDOStatement;
use RuntimeException;
use UnexpectedValueException;

/**
 * Base class for every repository that touches client data.
 *
 * FR-TEN-002 (mandatory tenant scoping) and AC-001 (a cross-tenant read is
 * impossible) are enforced here structurally, not by convention:
 *
 *   1. CONSTRUCTION IS THE GATE. The constructor builds a TenantScope, which
 *      throws on a null, zero or negative tenant. An instance of a subclass
 *      therefore cannot exist in an unscoped state - there is no later point
 *      at which someone "forgets" to scope, because there is no unscoped
 *      object to forget about.
 *
 *   2. SUBCLASSES CANNOT WRITE THE WHERE CLAUSE HEAD. They supply a table name
 *      and a column list; selectScoped()/updateScoped()/deleteScoped() build
 *      the statement and always prepend the scope predicate. A subclass's own
 *      predicate is ANDed after it, parenthesised (see TenantScope::where()).
 *
 *   3. THE TENANT VALUE IS BOUND INTERNALLY, LAST. Callers pass named
 *      parameters; a parameter named `tenant` is rejected outright rather than
 *      silently ignored, so no caller can choose the tenant it reads.
 *
 *   4. THE SCOPE IS IMMUTABLE. tenant_id is refused in an UPDATE SET list
 *      (FR-TEN-001), so an in-scope owner cannot hand a row to another tenant.
 *
 * WHY prepare()/execute() AND NEVER query()/exec(): those two PDO methods take
 * a finished SQL string, which means the tenant value would have to be
 * interpolated into it. That is both an injection surface and an unscoped-query
 * surface. build/phpstan/NoUnscopedClientQueryRule.php enforces this for the
 * whole codebase so the rule survives contributors who never read this comment.
 *
 * WHAT THIS CLASS DOES NOT DO: it is not an ORM and does not try to parse SQL.
 * Its guarantee is narrow and therefore checkable - every statement it emits
 * has the tenant predicate in it and the tenant value bound by the repository.
 *
 * © AI WebScapes 2026
 */
abstract class TenantRepository
{
    /**
     * Table and column names cannot be bound as parameters, so they are
     * interpolated - which means they must be validated. Anything that is not
     * a plain SQL identifier is refused rather than quoted, because a
     * repository has no legitimate reason to name a table with backticks,
     * spaces or a semicolon in it.
     */
    private const IDENTIFIER_PATTERN = '/^[A-Za-z_][A-Za-z0-9_]*$/';

    /**
     * Placeholders generated for an UPDATE's SET list are prefixed so they
     * cannot collide with a caller's WHERE parameter of the same name.
     */
    private const SET_PREFIX = 'set_';

    protected PDO $pdo;

    /**
     * Private, not protected: a subclass must not be able to swap the scope
     * after construction. Read it through tenantId() if it needs the value.
     */
    private TenantScope $scope;

    public function __construct(PDO $pdo, ?int $tenantId)
    {
        $this->pdo = $pdo;

        // Throws UnscopedQueryException for null / 0 / negative. Deliberately
        // the FIRST thing that can fail: an unscoped repository never exists.
        $this->scope = new TenantScope($tenantId);
    }

    /**
     * The client table this repository reads. Must be a bare SQL identifier.
     */
    abstract protected function table(): string;

    /**
     * The columns a plain listing selects. `SELECT *` is not offered: an
     * explicit list keeps the returned shape stable when the table grows.
     *
     * @return list<string>
     */
    abstract protected function columns(): array;

    public function tenantId(): int
    {
        return $this->scope->id();
    }

    /**
     * The SQL a plain listing would run, exposed for inspection and testing.
     *
     * Public on purpose: it lets a test assert that scoping is present in the
     * generated SQL itself (FR-TEN-002), rather than inferring it from an
     * empty result set - which an absent row would also produce.
     */
    public function listSql(): string
    {
        return $this->selectSql();
    }

    /**
     * Finds a single row by primary key, within the tenant scope.
     *
     * Returns null both when the row does not exist and when it belongs to
     * another tenant - the two are deliberately indistinguishable to the
     * caller (AC-001), because a distinguishable "exists but forbidden" is an
     * enumeration oracle for row ids across tenants.
     *
     * Subclasses whose key column is not `id` override this.
     *
     * @return array<string, scalar|null>|null
     */
    public function find(string $id): ?array
    {
        $rows = $this->selectScoped('id = :id', ['id' => $id]);

        return $rows[0] ?? null;
    }

    /**
     * The scoped SELECT statement. There is no code path that produces a
     * SELECT for this table without TenantScope::where() in it.
     */
    protected function selectSql(string $where = ''): string
    {
        return 'SELECT ' . implode(', ', $this->safeColumns())
            . ' FROM ' . $this->safeTable()
            . $this->scope->where($where);
    }

    /**
     * @param  array<string, scalar|null> $params
     * @return list<array<string, scalar|null>>
     */
    protected function selectScoped(string $where = '', array $params = []): array
    {
        $statement = $this->run($this->selectSql($where), $params);

        $rows = [];
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $rows[] = $this->normaliseRow($row);
        }

        return $rows;
    }

    /**
     * Scoped UPDATE. Returns the number of affected rows, which is 0 when the
     * target row belongs to another tenant - the write is refused by the
     * database, not by an application-level check that could be skipped.
     *
     * @param  array<string, scalar|null> $values Column => new value.
     * @param  array<string, scalar|null> $params Bindings for $where.
     * @return int Affected row count.
     */
    protected function updateScoped(array $values, string $where = '', array $params = []): int
    {
        if ($values === []) {
            throw new InvalidArgumentException('An UPDATE needs at least one column to set.');
        }

        $assignments = [];
        $bound = $params;

        foreach ($values as $column => $value) {
            // FR-TEN-001: the scope column is not writable through here.
            $this->scope->rejectTenantColumnWrite($column);

            $safe = $this->assertIdentifier($column, 'column');
            $placeholder = self::SET_PREFIX . $safe;

            if (array_key_exists($placeholder, $bound)) {
                throw new InvalidArgumentException(sprintf(
                    'Parameter ":%s" collides with the placeholder generated for '
                    . 'the SET assignment of column "%s". Rename the WHERE parameter.',
                    $placeholder,
                    $safe
                ));
            }

            $assignments[] = $safe . ' = :' . $placeholder;
            $bound[$placeholder] = $value;
        }

        $sql = 'UPDATE ' . $this->safeTable()
            . ' SET ' . implode(', ', $assignments)
            . $this->scope->where($where);

        return $this->run($sql, $bound)->rowCount();
    }

    /**
     * Scoped DELETE. Same guarantee as updateScoped(): a row outside the scope
     * is not reachable, so the affected count is 0 rather than an error.
     *
     * @param  array<string, scalar|null> $params
     * @return int Affected row count.
     */
    protected function deleteScoped(string $where = '', array $params = []): int
    {
        $sql = 'DELETE FROM ' . $this->safeTable() . $this->scope->where($where);

        return $this->run($sql, $params)->rowCount();
    }

    /**
     * Prepares, binds and executes. The single choke point through which every
     * statement this class emits must pass.
     *
     * @param array<string, scalar|null> $params
     */
    private function run(string $sql, array $params): PDOStatement
    {
        // Refuse before doing any work: a caller trying to bind :tenant is a
        // defect to surface, not a condition to work around.
        $this->scope->rejectCallerBinding($params);

        $statement = $this->pdo->prepare($sql);
        if ($statement === false) {
            // Unreachable under ERRMODE_EXCEPTION, which throws instead of
            // returning false. Kept so the class stays correct if a caller
            // hands in a PDO configured with a laxer error mode, and so static
            // analysis sees the false branch handled rather than assumed away.
            throw new RuntimeException(sprintf('Failed to prepare statement: %s', $sql));
        }

        foreach ($params as $name => $value) {
            $statement->bindValue(':' . ltrim($name, ':'), $value, $this->pdoType($value));
        }

        // LAST, and unconditionally. Ordering matters: even if a reserved
        // parameter somehow reached this point, the repository's own binding
        // is the one that lands.
        $this->scope->bindTo($statement);

        $statement->execute();

        return $statement;
    }

    /**
     * Maps a PHP value onto the PDO parameter type.
     *
     * Without this every binding defaults to PARAM_STR, which makes MySQL
     * compare an integer column against a quoted string - correct in result
     * but index-unfriendly, and it hides type mistakes.
     */
    private function pdoType(bool|float|int|string|null $value): int
    {
        return match (true) {
            $value === null => PDO::PARAM_NULL,
            is_bool($value) => PDO::PARAM_BOOL,
            is_int($value) => PDO::PARAM_INT,
            default => PDO::PARAM_STR,
        };
    }

    /**
     * Narrows one PDO::FETCH_ASSOC row to a checked, statically-known shape.
     *
     * PDO's return type is untyped `array`, so without this every value would
     * enter the application as `mixed` and level-8 analysis would be blind
     * from the repository boundary outward.
     *
     * @return array<string, scalar|null>
     */
    private function normaliseRow(mixed $row): array
    {
        if (!is_array($row)) {
            throw new UnexpectedValueException('Expected an associative row from PDO::FETCH_ASSOC.');
        }

        $clean = [];
        foreach ($row as $column => $value) {
            if (!is_string($column)) {
                throw new UnexpectedValueException(
                    'Expected string column names; PDO::FETCH_ASSOC was not honoured.'
                );
            }

            if ($value !== null && !is_scalar($value)) {
                throw new UnexpectedValueException(sprintf(
                    'Column "%s" produced a non-scalar value, which no client column declares.',
                    $column
                ));
            }

            $clean[$column] = $value;
        }

        return $clean;
    }

    private function safeTable(): string
    {
        return $this->assertIdentifier($this->table(), 'table');
    }

    /**
     * @return list<string>
     */
    private function safeColumns(): array
    {
        $columns = $this->columns();
        if ($columns === []) {
            throw new InvalidArgumentException(
                'A repository must declare at least one column to select.'
            );
        }

        $safe = [];
        foreach ($columns as $column) {
            $safe[] = $this->assertIdentifier($column, 'column');
        }

        return $safe;
    }

    private function assertIdentifier(string $identifier, string $kind): string
    {
        if (preg_match(self::IDENTIFIER_PATTERN, $identifier) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'Refusing to interpolate "%s" as a %s name: only plain SQL '
                . 'identifiers (letters, digits, underscore, not starting with '
                . 'a digit) are accepted.',
                $identifier,
                $kind
            ));
        }

        return $identifier;
    }
}
