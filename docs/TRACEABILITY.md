# Traceability Matrix — Aiwebscapes Platform (Phase 1)

This matrix maps each Phase-1 requirement to the shipped code that satisfies it.
It is the release-gate item "traceability matrix complete" (plan §995). T1–T14
rows are summarised; **P1-T15 is the only task still being closed in this
session** (the rest are already committed — see `docs/HANDOFF.md` and
`docs/SESSION_HANDOFF_P1T14.md`).

## P1-T15 — Dashboard + WCAG 2.2 AA (FR-DASH-001/002, LFR-DASH-001/002/003, A11Y-001..006)

| Requirement | Where satisfied | Verified by |
|---|---|---|
| FR-DASH-001 (dashboard exposes pipeline state + counts) | `src/Dashboard/DashboardRepository::leadStatusCounts()`, `DashboardController::renderHtml()` table | `tests/Dashboard/PipelineTest::test_lead_status_counts_are_scoped_and_accurate` |
| FR-DASH-002 (status conveyed without colour alone) | `DashboardController` renders text label + distinct icon, icon `aria-hidden="true"` | `tests/Dashboard/AccessibilityTest::test_status_not_color_only` |
| LFR-DASH-001 (pipeline exposes all states) | `DashboardRepository::LEAD_STATES` (5 states matching `migrations/005_leads.sql` ENUM) | `tests/Dashboard/PipelineTest::test_pipeline_exposes_all_five_states` |
| LFR-DASH-002 (awaiting-human queue) | `DashboardRepository::awaitingHuman()` → `lead_ai_analyses.status='pending'` | `tests/Dashboard/PipelineTest::test_dashboard_shows_awaiting_human_queue` + `::test_awaiting_human_is_tenant_scoped` |
| LFR-DASH-003 (failed-delivery queue) | `DashboardRepository::failedDeliveries()` → `message_deliveries.status='failed'` (columns added in `migrations/009_dashboard.sql`) | `tests/Dashboard/PipelineTest::test_dashboard_shows_failed_deliveries` + `::test_failed_deliveries_are_tenant_scoped` |
| A11Y-001 (perceivable: lang/title/headings/landmarks) | `<html lang="en">`, `<title>`, single `<h1>`, `role=banner/main/contentinfo` | `tests/Dashboard/AccessibilityTest::test_page_is_perceivable` |
| A11Y-002 (keyboard operable, visible focus) | native controls, `:focus-visible` 3px outline, skip link, no autofocus | `tests/Dashboard/AccessibilityTest::test_all_controls_keyboard_operable` |
| A11Y-003 (form errors programmatically determinable) | `leadFormHtml()` `aria-invalid` + `aria-describedby` → `role="alert"` | `tests/Dashboard/AccessibilityTest::test_form_errors_programmatically_determinable` |
| A11Y-004 (not colour-only — see FR-DASH-002) | same as FR-DASH-002 | same as FR-DASH-002 |
| A11Y-005 (contrast ≥ 4.5:1) | `#1a1a1a`/white ≈17:1, `#0b5cab` link ≈5.9:1, `#b00020` error ≈5.9:1 | manual a11y pass (A11Y-006) |
| A11Y-006 (manual keyboard/AT pass) | manual checklist performed 2026-08-08 (see HANDOFF §T15) | manual record |
| AC-001 (tenant isolation of dashboard data) | every read goes through `TenantScope::where()`/`bindTo()`; cross-tenant negative tests | `tests/Dashboard/PipelineTest::test_*_is_tenant_scoped` |
| LBR-5.8 (exceptions queue for humans) | `awaitingHuman()` + `failedDeliveries()` feeds the dashboard queues | `tests/Dashboard/PipelineTest` queue tests |

## P2-T1 — Evaluation harness + eval-gated activation (FR-AGENT-003)

| Requirement | Where satisfied | Verified by |
|---|---|---|
| FR-AGENT-003 (prompt/config change = new immutable version) | `AgentRegistry::updatePrompt()` → `AgentVersionRepository` (append-only) | `AgentRegistryTest::test_prompt_change_creates_new_version` (built P1-T5) |
| FR-AGENT-003 (evaluation gates production activation) | `EvaluationReleaseGate::release()` records eval row then calls `activate(evalPassed)` | `AgentRegistryTest::test_evaluation_passed_records_run_and_activates` / `::test_evaluation_failed_records_run_and_blocks_activation` |
| BRD Table 4 "AI quality" KPI dimensions | `config/eval/GOLDEN_SUITE.php` + `EvalHarness` threshold compare | `EvalHarnessTest::test_passing_measurements_clear_the_gate` |
| Gate not vacuous | weakening a KPI fails the run | `EvalHarnessTest::test_closing_one_threshold_fails_the_gate` |
| AC-003 (no side effect on invalid output) | invalid output forces `harmful_invalid_rate=1.0`, gate fails; harness holds only gateway + source | `EvalHarnessTest::test_schema_invalid_output_is_harmful_and_fails` |
| Append-only eval evidence | `agent_evaluations` ledger (migration 010), `AgentEvaluationRepository` | `AgentRegistryTest::test_evaluation_*_records_run_*` |

### Deviance from plan skeleton (P1-T15) — must-read

The plan's T15 test skeleton assumed artifacts the as-built platform does NOT
have. Each was reconciled **toward the built security guarantee** (owner
directive) rather than expanding scope:

1. **Lead pipeline = 5 states, not 10.** The plan text lists 10
   (`New,Processing,Review,Contacted,Qualified,Scheduled,Won,Lost,Spam,Archived`)
   but `migrations/005_leads.sql` defines `leads.status` as a 5-value ENUM
   (`New,Review,Qualified,Disqualified,Converted`) and no prior task implemented
   the 10-state model. T15 asserts the **real** 5 states; it does NOT mutate the
   domain model. If the 10-state pipeline is wanted later, that is a new
   migration + task, not a T15 scope change.
2. **No Slim kernel / Twig / `public/index.php` existed.** Every controller is
   array-in/array-out and tested directly (`src/Leads/LeadController` is the
   template). T15 followed that convention: `DashboardController` is
   array-in/out; the dashboard HTML is rendered by a pure method
   (`renderHtml()`) with a single `htmlspecialchars()` escape sink (SEC-010). A
   minimal `public/index.php` front controller was added ONLY to satisfy the
   axe-core served-page gate; tenant identity is server-fixed (`APP_TENANT_ID`),
   never request-derived (AC-001).
3. **`message_deliveries` had no dispatch outcome.** A failed delivery had no
   signal to read, so `failedDeliveries()` would have been vacuous.
   `migrations/009_dashboard.sql` adds nullable `status` + `error` columns
   (idempotent, information_schema-guarded) so the queue is real data.

## Phase-1 Exit Gate (plan §995) — status after T15

- [x] Suite green (201 tests, 524 assertions) on isolated DB — phpunit OK.
- [x] phpstan L8 `[OK] No errors`; phpcs 0 errors (pre-existing line-length warnings only).
- [x] composer audit: no vulnerabilities; gitleaks: no leaks.
- [x] axe-core 4.13.0: 0 WCAG 2.2 AA violations (automated).
- [x] Manual a11y pass (A11Y-006) recorded 2026-08-08.
- [~] AC-001/002/003 negative tests present (T3/T8/T6 respectively) and green.
- [~] Lead MVP 12-step E2E + Lead FRD Table 4 cases — owned by T10–T12 suites (not T15).
- [ ] Owner push of T13 (`e3cfc07`) + T14 (`b9eefd1`) — pending owner action.
- [ ] Pen-test window (SEC-009 / SFR-AUTH-001) — OPEN, book before release.
- [ ] SLA numbers / performance budgets (NFR Table 5) — OPEN, owner input.
- [ ] SEC-008 branch protection — BLOCKED by GitHub Free tier; documented OPEN, not skipped.
