<?php

declare(strict_types=1);

namespace App\Console;

/**
 * The single escape sink for every console-rendered page.
 *
 * WHY ONE SHARED SINK AND NOT A PRIVATE METHOD PER VIEW. The dashboard carries
 * its own private escapeSink() because it is one class rendering one page. The
 * console is several pages (login, agent list, invocation result) that all
 * interpolate the same untrusted values - agent names, owners, purposes, model
 * output - so a per-view copy would mean N chances to forget one, and the
 * forgotten one is the injection. One static sink makes "every value is
 * escaped" a property of the codebase rather than a habit.
 *
 * ENT_QUOTES | ENT_HTML5 is not decoration: ENT_QUOTES closes the
 * attribute-injection path (an unescaped double quote inside a value="..."
 * attribute is a new attribute), and ENT_HTML5 covers the modern named
 * entities. This matches App\Dashboard\DashboardController::escapeSink() so
 * there is one escaping behaviour across the platform, not two.
 *
 * © AI WebScapes 2026
 */
final class Html
{
    public static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}
