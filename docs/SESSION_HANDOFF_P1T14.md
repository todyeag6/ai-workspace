# Deviation Record: P1-T15 Dashboard — Slim + Twig → testable inline-HTML front controller

- **Status:** Recorded (historical deviation from plan P1-T15)
- **Date:** 2026-08-05
- **Decider:** Aiwebscapes engineering
- **Related:** Plan P1-T15; `public/index.php`; `src/Dashboard/*`; FR-DASH-001/002; LFR-DASH-001/002/003; A11Y-001..006; AC-001; SEC-010

> This file is a **decision record**, not a status report. Mutable state
> (test counts, push state, HEAD) is intentionally absent; derive it with
> `bash scripts/status.sh`. It exists to resolve the dangling reference cited
> by `public/index.php` and `src/Dashboard/DashboardRepository.php`.

---

## 1. Context

The P1-T15 plan skeleton assumed a Slim kernel plus a Twig template served at
`/dashboard`. During the build the as-built platform settled on a different
shape: every controller is array-in / array-out and is tested directly, with
**no web kernel** in the running application. Standing up an entire framework
(Slim container boot, router, Twig loader) to serve one page would add
unbuilt scope and a fresh attack surface for no functional gain.

The dashboard still had to meet its real requirements: a WCAG 2.2 AA operations
view of the lead pipeline plus the two human-decision queues, tenant-scoped and
injection-safe.

## 2. Decision

Implement the dashboard as a **thin, testable front controller**
(`public/index.php`) that renders through
`App\Dashboard\DashboardController::renderHtml()` — a pure string-HTML builder.

- Presentational HTML is produced by a single method that performs no I/O and
  has exactly one escape sink (`escapeSink()` → `htmlspecialchars`), so the WCAG
  guarantees are unit-testable without MySQL.
- Twig is **not** introduced for this page. The plan's "Twig" step for P1-T15 is
  superseded.
- Tenant identity is fixed by the server (`APP_TENANT_ID`), never derived from
  the request (AC-001). Every repository read is bound through
  `App\Tenancy\TenantScope` (FR-TEN-002).
- `public/index.php` is a demo/accessibility gate only — it is not the
  production entrypoint and is not wired into any auth flow.

## 3. Requirement coverage (unchanged intent)

| Requirement | How the as-built dashboard satisfies it |
|-------------|------------------------------------------|
| FR-DASH-001 | `leadStatusCounts()` — per-state pipeline counts. |
| FR-DASH-002 | Pipeline table + two exception queues (awaiting-human, failed-deliveries). |
| LFR-DASH-001 | `states()` exposes the canonical five lead states, in order. |
| LFR-DASH-002/003 | Satisfied by `App\Leads\LeadDashboard` (filter + detail read models); not yet wired into this page. |
| A11Y-001 | `lang`, single `<h1>`, `<title>`, skip link. |
| A11Y-002 | Native controls, no keyboard trap, `:focus-visible` styling. |
| A11Y-003 | Form errors via `aria-invalid` + `aria-describedby` → `role="alert"`. |
| A11Y-004 | Status conveyed by text + icon, never colour alone. |
| A11Y-005/006 | Reduced-motion CSS + manual AT pass (see Gate B in the deck handoff). |
| AC-001 | Tenant fixed server-side; repository I/O `TenantScope`-bound. |
| SEC-010 | Single `htmlspecialchars` escape sink for all interpolated values. |

## 4. Consequences

- No Slim kernel or Twig runtime exists for the dashboard, by choice.
- Markup is string-built, so template-inheritance tooling is unavailable here;
  `tests/Dashboard/AccessibilityTest.php` + `PipelineTest.php` cover the same
  guarantees a served page would.
- If a Slim + Twig web kernel is stood up later for the broader UI, this page
  can be ported to a `.twig` template without changing its data path
  (`DashboardView` / `DashboardRepository` stay as-is).

## 5. Verification

State is derived, not written here. Run `bash scripts/status.sh` for current
test/push status. The Dashboard suite under `tests/Dashboard/` is the gate for
this task; PHPStan is configured to analyse `src/Dashboard`.
