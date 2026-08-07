# Next-Session Prompt — Aiwebscapes Platform Phase 1

> **Copy everything below the line into a fresh Hermes session as the first message.**
> It encodes the plan, live repo state, environment gotchas, and the development
> best practices (TDD + subagent-driven-development + database-test-isolation)
> proven during Phase 0–1. Follow it literally.

---

You are continuing the **Aiwebscapes Platform** build. This is a hardened PHP 8 / MySQL 8 / Redis production system built from a legacy baseline, executed against an approved plan. Phase 0 (foundation hardening) is COMPLETE and green, and **Phase-1 tasks T1–T14 are DONE** (verified on isolated DBs). Your job is to finish **P1-T15** (Dashboard + WCAG 2.2 AA), then reach the **Phase 1 exit gate**.

## 0. Load these skills first (mandatory)
Call `skill_view` on each before you start building:
- `subagent-driven-development` — one fresh subagent per task, full context inline, TDD, then two-stage review (spec-compliance, then code-quality). Never skip reviews.
- `test-driven-development` — RED before GREEN, non-negotiable.
- `database-test-isolation` — idempotent migrations + DDL-leak loud guard (the base `TestCase` re-applies all migrations before every test).
- `php-docker-tested-build` — Windows-MSYS environment gotchas, gate commands, and the "never trust stale green" rule.

## 1. Ground truth (do NOT re-derive)
- **Host:** Windows 10, `terminal` = bash (git-bash/MSYS), NOT PowerShell. POSIX paths (`/c/Users/...`). `E:` is exFAT and mounts silently empty — keep everything on `C:`.
- **Repo:** `C:\Users\CTYea\dev\aiwebscapes-platform`, branch `main`, tree clean. Phase 1 progress: **T1–T14 DONE** (191 tests, 489 assertions green, verified on isolated DBs). `origin/main` has T1–T12 (`81e99d4`); **T13 (`e3cfc07`) and T14 (`b9eefd1`) are local-only, pending owner push**. Next is **P1-T15** (Dashboard + WCAG 2.2 AA).
- **No PHP/Composer/mysql on host.** Everything via `docker compose exec -T app ...` (ALWAYS `-T`).
- **Stack:** `app` (php:8.3-cli, `sleep infinity`, `.:/app`), `db` (mysql:8, `3307:3306`), `redis` (7). DSNs: `TEST_DB_DSN=mysql:host=db;dbname=aiwebscapes_test`. `AI_LOCAL_BASE_URL=http://host.docker.internal:11434/v1` (Ollama, GTX 1660 Ti 6GB — **never `gemma4:12b`**).
- **GitHub remote EXISTS** — `origin = https://github.com/todyeag6/ai-workspace.git`. Pushing is the OWNER's call: do NOT `git push`/`force-push` without an explicit per-occasion instruction.
- **Plan (source of truth):** `C:\Users\CTYea\.hermes\plans\2026-08-05_100000-aiwebscapes-production-system-plan.md` (1,180 lines; Phase 1 starts ~line 510).
- **Handoff + live state:** `docs/SESSION_HANDOFF_P1T14.md` in this repo (covers T12–T14 results, migration-number drift, and the stray-DB cleanup backlog). `docs/HANDOFF.md` holds the standing standards-baseline reconciliation.
- **Requirement text (authoritative):** `C:\Users\CTYea\awsx_docs\` `.docx` — PDFs are duplicates, never read; `_awsx_extract/*.txt` are derived, never treat as source of truth.

## 2. Boot the stack (first action)
```bash
cd /c/Users/CTYea/dev/aiwebscapes-platform
docker compose up -d          # applies restart:unless-stopped; wait ~30s for db healthy
docker compose exec -T app vendor/bin/phpunit   # expect OK (191 tests, 489 assertions)
```
If phpunit REDs with `getaddrinfo for db/redis failed`, the containers are down — run `docker compose up -d` again (do NOT go hunting for a code bug; this is the known daily-exit behavior, now self-healing via `restart: unless-stopped`).

## 3. Phase 1 scope + the linchpin rule
**Plan directive (verbatim):** *"Tenancy first. Do not build features before P1-T4 passes — every later requirement inherits AC-001."* Tenancy (P1-T3/T4) is DONE and proven; the PHPStan `NoUnscopedClientQueryRule` forbids raw client queries.

Tasks (T1–T14 DONE; T15 remains):
- **P1-T1** Tenant + identity schema — ✅ `cf00ca8`
- **P1-T2** Password hasher (argon2id) — ✅
- **P1-T3** TenantScope + repository base (AC-001) — ✅ `3a69497`+
- **P1-T4** Auth service + tenant authz (SEC-005, AC-001) — ✅ `88d4095`
- **P1-T5** Agent registry — ✅ `90ccdb3`
- **P1-T6** AI Gateway + schema validation (AC-003) — ✅ `297e915`
- **P1-T7** Local + cloud adapters, router, injection filter — ✅ `db2be7e`
- **P1-T7.5** Single-resident model policy + 8192 ceiling — ✅ `1c25f00`
- **P1-T8** Tool/Connector Gateway (AC-002, SSRF) — ✅ `a9a4b3b`
- **P1-T9** Workflow orchestrator (idempotency, FR-AI-006) — ✅ `1aa7db3`
- **P1-T10** Lead schema + persist-before-AI capture (LBR-5.1) — ✅ `5dc7b63`
- **P1-T11** Duplicates, AI analysis, routing — ✅ `be3855e`
- **P1-T12** Messaging, tasks, corrections, privacy — ✅ `81e99d4` (PUSHED)
- **P1-T13** Audit/notifications/observability/retention — ✅ `e3cfc07` (LOCAL-ONLY, pending push). Append-only via MySQL `BEFORE UPDATE/DELETE` `SIGNAL` triggers (`migrations/007_audit.sql`); `src/Infra/SqlSplitter.php` made the migration runner DELIMITER-aware.
- **P1-T14** Assessment + BAAF scoring — ✅ `b9eefd1` (LOCAL-ONLY, pending push). `migrations/008_assessment.sql` (plan said `007` but `007` taken); fail-closed BAAF gates BAAF-003/004/005/006 + §3.
- **P1-T15** Dashboard + WCAG 2.2 AA (FR-DASH-001/002, LFR-DASH-001/002/003, A11Y-001..006). `src/Dashboard/DashboardController.php` + twig + `public/index.php`. **Manual a11y pass MANDATORY** (axe-core alone insufficient). Commit: per plan.

## 4. Workflow (best practice — follow exactly)
For EACH task:
1. Read the task block in the plan. Extract the FULL task text + test skeletons + requirement IDs.
2. **Dispatch an implementer subagent** (`delegate_task`, leaf) with: full task text inline, the environment ground truth (§1), TDD instructions (write failing test first → run → implement → re-run GREEN → commit), and the relevant gotchas from `php-docker-tested-build`.
3. **RED before GREEN:** the subagent MUST paste RED output, then GREEN. A task without a failing-test-first proof is not done.
4. **Two-stage review** (dispatch two reviewers, or run sequentially): (a) **spec-compliance** — every named requirement ID quoted verbatim, every deliverable file present, no scope creep; (b) **code-quality** — PSR-12 (snake_case test methods excluded for `tests/*` only), PHPStan level 8 over `src`+`tests`, no two-classes-per-file, no `require`-as-misuse confusion (it's a valid method name).
5. Proceed ONLY when both reviews approve. Mark the todo complete.
6. After the task, run `bash scripts/ci-local.sh` to keep the gate green.

## 5. Non-negotiable gates (keep green every task)
```bash
docker compose exec -T app vendor/bin/phpunit                              # OK (N tests, M assertions)
docker compose exec -T app vendor/bin/phpcs --standard=phpcs.xml src tests # 0 errors
docker compose exec -T app vendor/bin/phpstan analyse --no-progress        # [OK] No errors
bash scripts/ci-local.sh                  # ALL LOCAL CI GATES PASSED (6/6: phpcs, phpstan, composer audit, SBOM, gitleaks, phpunit)
```
- **Migrations idempotent:** `CREATE TABLE IF NOT EXISTS`, inline indexes, guarded seed `INSERT`s, `DROP ... IF EXISTS`. `TestCase` re-applies all `migrations/*.sql` before every test (via `App\Infra\SqlSplitter`).
- **Trigger migrations** must keep the `DELIMITER $$ … DELIMITER ;` block — `SqlSplitter` handles it (naive `explode(';')` would break trigger bodies).
- **gitleaks** runs from HOST (not container); `.gitleaks.toml` allowlists `vendor/`, `*.phar`, lockfiles, `sbom.xml` — real source is still scanned. An empty bind mount false-passes; confirm non-zero byte scan.

## 6. Critical disciplines (learned the hard way — do not repeat)
- **Never trust last session's green.** Before claiming green or starting, **re-run the FULL gate including `composer audit`** — advisories appear over time. After any major dep bump, re-verify the phpcs ruleset still passes.
- **Subagent summaries are advisory, not ground truth.** Async subagents hit HTTP 429/524 and **time out before committing** (work lands untracked), or report **stale state** from a concurrent sibling's mid-flight phase. Always re-verify repo state with real `git`/`phpunit` commands and finish/commit yourself when an agent dies.
- **Verify claims with real tool output**, never summarize from memory. Produce ad-hoc verification via a temp script named with the `hermes-verify-` prefix in `%TEMP%`, run it, report `VERIFY_EXIT`, then delete it.
- **CRLF:** `.gitattributes` is committed — do not remove it. `.sh` files must be LF in-container.
- **`mysql-client`** in the Dockerfile (binary `mysql`), NOT `default-mysql-client`.
- **Stray iso/verify DBs do NOT self-clean** (Docker volume). ~19 from T13/T14 verification remain; see `docs/SESSION_HANDOFF_P1T14.md` Cleanup backlog. Drop only with owner consent.

## 7. OPEN QUESTIONS — resolve BEFORE Phase-1 exit (plan §7)
1. SLA numbers + performance budgets (NFR Table 5) — needed for release-gate item 7.
2. Pen-test window + authorizing party + environment (SEC-009, SFR-AUTH-001) — book before Phase 1 exit; it's a release gate.
3. Standards register cadence — owner + next review date.
4. First tenant's data classes — drives LFR-AI-002 redaction config.
5. **SEC-008 branch protection is BLOCKED by the GitHub Free tier** (both legacy + rulesets APIs return `403 "Upgrade to GitHub Pro"`). Stay private + free; owner pushes own. Document SEC-008 as OPEN, not skipped.

## 8. Stop condition
Reach the **Phase 1 Exit Gate** (plan §995): suite green in BOTH cloud and local-Ollama configs (AC-006); AC-001/002/003 proven by negative tests; lead MVP 12-step E2E in one integration test; 10 Lead FRD Table 4 cases pass; axe-core + manual a11y; CI green + SBOM + no critical findings; threat model updated for AI gateway + tool egress; traceability matrix complete. **Do not drift into Phase 2+.** After T15: owner pushes T13 + T14, then the exit gate. Update `docs/HANDOFF.md`, `docs/SESSION_HANDOFF_P1T14.md`, and `docs/TRACEABILITY.md` for the next session.

## 9. First concrete step
Boot the stack (§2), confirm phpunit is green (191 tests, 489 assertions), then begin **P1-T15** (Dashboard + WCAG 2.2 AA) with a failing test first. Report the boot result with real output before doing anything else.
