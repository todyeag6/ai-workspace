<?php

declare(strict_types=1);

namespace App\Infra;

/**
 * Splits a migration file into executable statements.
 *
 * REPLACES the naive `explode(';', $sql)` that both tests/TestCase.php and
 * scripts/migrate.php used before P1-T13. The old splitter could not parse a
 * semicolon inside a string literal or a DELIMITER block, so migrations were
 * forbidden to contain them. P1-T13 needs triggers - and the plan itself
 * notes (scripts/migrate.php) "When P1-T13 introduces triggers this has to be
 * replaced with a real parser - in both places." This is that replacement.
 *
 * It is a real, small parser:
 *   - Tracks whether the current statement is inside a single- or double-quoted
 *     string literal; semicolons inside literals do NOT split the statement.
 *   - Honours an explicit `DELIMITER` directive (case-insensitive, alone on a
 *     line) and splits on the NEW delimiter until the next DELIMITER reverts it.
 *   - Strips `--` and `#` line comments and `/* *\/` block comments BEFORE
 *     scanning, so a semicolon inside prose does not split a statement either.
 *   - Trailing comments are removed from each emitted statement.
 *
 * WHY this matters for security: append-only audit enforcement (FR-AUD-001)
 * is implemented as MySQL BEFORE UPDATE / BEFORE DELETE triggers that SIGNAL.
 * A trigger body contains semicolons, so the naive splitter would have shattered
 * it - the very reason migration 002 banned triggers. Upgrading the splitter is
 * what lets the database itself refuse tampering, which the application layer
 * alone could not guarantee.
 *
 * © AI WebScapes 2026
 */
final class SqlSplitter
{
    /**
     * The delimiter the parser currently splits on. Starts at ';' and changes
     * only when a `DELIMITER` directive is encountered.
     */
    private string $delimiter = ';';

    /**
     * @return list<string> Non-empty, trimmed statements, in file order.
     */
    public function statements(string $sql): array
    {
        $sql = $this->stripComments($sql);

        /** @var list<string> $statements */
        $statements = [];
        $buffer = '';
        $length = strlen($sql);
        $inSingle = false;
        $inDouble = false;
        $lineStart = 0;

        for ($i = 0; $i < $length; $i++) {
            $char = $sql[$i];

            // A `DELIMITER <token>` directive is honoured only when it appears
            // on its own line. The moment we reach a newline we know the line
            // that just ended; if it was a directive, consume it (switch the
            // split point) and start a fresh buffer. Doing this inside the
            // scanner - not only at the very end of statements() - is what
            // keeps the directive from being emitted as a statement.
            if ($char === "\n") {
                $line = trim(substr($sql, $lineStart, $i - $lineStart));
                $lineStart = $i + 1;
                if ($this->isDelimiterDirective($line)) {
                    $buffer = '';
                    continue;
                }
            }

            if ($inSingle) {
                $buffer .= $char;
                if ($char === '\\' && $i + 1 < $length) {
                    $buffer .= $sql[++$i]; // consume escaped char verbatim
                } elseif ($char === "'") {
                    $inSingle = false;
                }
                continue;
            }

            if ($inDouble) {
                $buffer .= $char;
                if ($char === '\\' && $i + 1 < $length) {
                    $buffer .= $sql[++$i];
                } elseif ($char === '"') {
                    $inDouble = false;
                }
                continue;
            }

            if ($char === "'") {
                $inSingle = true;
                $buffer .= $char;
                continue;
            }

            if ($char === '"') {
                $inDouble = true;
                $buffer .= $char;
                continue;
            }

            // A delimiter we recognise always ends at length 1; longer
            // delimiters (e.g. '$$') still match here because we check the
            // substring starting at $i.
            //
            // IMPORTANT: the delimiter is ONLY a splitting marker. It is NEVER
            // forwarded to the database. Over PDO each exec() carries exactly
            // one statement, so a trailing terminator would be a syntax error
            // (and `DELIMITER` is a mysql-cli keyword the server does not
            // recognise at all). A `DELIMITER <token>` line is therefore
            // consumed as a directive - it switches our split point and is not
            // emitted.
            $tail = substr($sql, $i, strlen($this->delimiter));
            if ($tail === $this->delimiter) {
                $i += strlen($this->delimiter) - 1;
                $statement = trim($buffer);
                $buffer = '';
                if ($statement !== '' && !$this->isDelimiterDirective($statement)) {
                    $statements[] = $statement;
                }
                continue;
            }

            $buffer .= $char;
        }

        // A DELIMITER directive can legitimately appear on the very last line
        // with no statement after it; otherwise a trailing non-delimiter tail
        // is emitted as the final statement. Never forward the delimiter.
        $tail = trim($buffer);
        if ($tail !== '' && !$this->isDelimiterDirective($tail)) {
            $statements[] = $tail;
        }

        return $statements;
    }

    /**
     * Removes MySQL `--` and `#` line comments and `/* ... *\/` block comments.
     * Applied before scanning so prose semicolons and comment markers never
     * influence splitting. A `--` inside a string is NOT a comment because
     * stripComments itself skips over string literals.
     */
    private function stripComments(string $sql): string
    {
        $out = '';
        $length = strlen($sql);
        $inSingle = false;
        $inDouble = false;
        $inBlock = false;

        for ($i = 0; $i < $length; $i++) {
            $char = $sql[$i];
            $next = $i + 1 < $length ? $sql[$i + 1] : '';

            if ($inBlock) {
                if ($char === '*' && $next === '/') {
                    $inBlock = false;
                    $i++;
                }
                continue;
            }

            if ($inSingle) {
                $out .= $char;
                if ($char === '\\' && $next !== '') {
                    $out .= $next;
                    $i++;
                } elseif ($char === "'") {
                    $inSingle = false;
                }
                continue;
            }

            if ($inDouble) {
                $out .= $char;
                if ($char === '\\' && $next !== '') {
                    $out .= $next;
                    $i++;
                } elseif ($char === '"') {
                    $inDouble = false;
                }
                continue;
            }

            if ($char === "'") {
                $inSingle = true;
                $out .= $char;
                continue;
            }

            if ($char === '"') {
                $inDouble = true;
                $out .= $char;
                continue;
            }

            if ($char === '/' && $next === '*') {
                $inBlock = true;
                $i++;
                continue;
            }

            // Line comments: trim the rest of the line.
            if ($char === '-' && $next === '-') {
                while ($i < $length && $sql[$i] !== "\n") {
                    $i++;
                }
                continue;
            }
            if ($char === '#') {
                while ($i < $length && $sql[$i] !== "\n") {
                    $i++;
                }
                continue;
            }

            $out .= $char;
        }

        return $out;
    }

    /**
     * A bare `DELIMITER <token>` line switches the split delimiter. Recognised
     * only when it is the entire trimmed line (the directive is never inside a
     * statement body in a migration).
     */
    private function isDelimiterDirective(string $line): bool
    {
        if (preg_match('/^DELIMITER\s+(\S+)$/i', $line, $matches) === 1) {
            $this->delimiter = $matches[1];

            return true;
        }

        return false;
    }
}
