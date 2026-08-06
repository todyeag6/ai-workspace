# Next-Session Prompt — Aiwebscapes Platform Phase 1

> **Copy everything below the line into a fresh Hermes session as the first message.**
> It encodes the plan, live repo state, environment gotchas, and the development
> best practices (TDD + subagent-driven-development + database-test-isolation)
> proven during Phase 0. Follow it literally.

---

You are continuing the **Aiwebscapes Platform** build. This is a hardened PHP 8 / MySQL 8 / Redis production system built from a legacy baseline, executed against an approved plan. Phase 0 (foundation hardening) is COMPLETE and green. Your job is **Phase 1: Multi-Tenant Core + Lead Follow-Up MVP** (tasks P1-T1 … P1-T15), then stop at the Phase 1 exit gate.

## 0. Load these skills first (mandatory)
Call `skill_view` on each before you start building:
- `subagent-driven-development` — one fresh subagent per task, full context inline, TDD, then two-stage review (spec-compliance, then code-quality). Never skip reviews.
- `test-driven-development` — RED before GREEN, non-negotiable.
- `database-test-isolation` — idempotent migrations + DDL-leak loud guard (the base `TestCase` re-applies all migrations before every test).
- `php-docker-tested-build` — Windows-MSYS environment gotchas, gate commands, and the "never trust stale green" rule.

## 1. Ground truth (do NOT re-derive)
- **Host:** Windows 10, `terminal` = bash (git-bash/MSYS), NOT PowerShell. POSIX paths (`/c/Users/...`). `E:` is exFAT and mounts silently empty — keep everything on `C:`.
- **Repo:** `C:\Users\CTYea\dev\aiwebscapes-platform`, branch `main`, 16 commits, tree clean (`vendor/` + `.phpunit.cache/` untracked only).
- **No PHP/Composer/mysql on host.** Everything via `docker compose exec -T app ...` (ALWAYS `-T`).
- **Stack:** `app` (php:8.3-cli, `sleep infinity`, `.:/app`), `db` (mysql:8, `3307:3306`), `redis` (7). DSNs: `TEST_DB_DSN=mysql:host=db;dbname=aiwebscapes_test`. `AI_LOCAL_BASE_URL=http://host.docker.internal:11434/v1` (Ollama, GTX 1660 Ti 6GB — **never `gemma4:12b`**).
- **No GitHub remote.** Never `git push`/`remote add`/`gh`. Commit locally. CI is proven via `scripts/ci-local.sh`, not GitHub.
- **Plan (source of truth):** `C:\Users\CTYea\.hermes\plans\2026-08-05_100000-aiwebscapes-production-system-plan.md` (1,180 lines; Phase 1 starts ~line 510).
- **Handoff + live state:** `docs/HANDOFF.md` in this repo (covers today's infra fixes + open questions).
- **Requirement text:** `C:\Users\CTYea\.hermes\_awsx_extract/*.txt` (7 files; traceability matrix seeds 168 requirements).

## 2. Boot the stack (first action)
```bash
cd /c/Users/CTYea/dev/aiwebscapes-platform
docker compose up -d          # applies restart:unless-stopped; wait ~30s for db healthy
docker compose exec -T app vendor/bin/phpunit   # expect OK (18 tests, 47 assertions)
```
If phpunit REDs with `getaddrinfo for db/redis failed`, the containers are down — run `docker compose up -d` again (do NOT go hunting for a code bug; this is the known daily-exit behavior, now self-healing via `restart: unless-stopped`).

## 3. Phase 1 scope + the linchpin rule
**Plan directive (verbatim):** *"Tenancy first. Do not build features before P1-T4 passes — every later requirement inherits AC-001."* Build and PROVE tenancy (P1-T3/T4) before any feature above them; enforce with a PHPStan rule, not discipline.

Tasks (from plan §Phase 1, full text + test skeletons are in the plan — read each task block before dispatching):
- **P1-T1** Tenant + identity schema (FR-TEN-001, FR-IDENT-*) — `migrations/001_tenants_identity.sql`; legacy `users.email UNIQUE` → `(tenant_id,email)`.
- **P1-T2** Password hasher (FR-IDENT-002) — `src/Identity/PasswordHasher.php`, **argon2id**, rehash-on-upgrade.
- **P1-T3** TenantScope + repository base (FR-TEN-002, AC-001) — unscoped queries structurally impossible; add PHPStan rule forbidding raw `->query()`/`->exec()` on client tables outside `TenantRepository`.
- **P1-T4** Auth service + tenant authz middleware (FR-IDENT-001/003/004, SEC-005, AC-001) — **deny-by-default**; 403 for BOTH "wrong tenant" and "not found" (no ID enumeration).
- **P1-T5** Agent registry (FR-AGENT-001/002/003) — disabled-by-default, versioning.
- **P1-T6** AI Gateway + schema validation (FR-AI-002/003, AC-003) — invalid output → `disposition='review'`, never a side effect.
- **P1-T7** Local + cloud adapters, local-first router, injection filter (FR-AI-001/004/005/006) — default `qwen3:4b`, quality `hermes3:8b`.
- **P1-T8** Tool/Connector Gateway (FR-TOOL-001/002/003, AC-002) — allowlists not denylists; SSRF egress guard.
- **P1-T9** Workflow orchestrator (FR-ORCH-001/002/003) — Redis `SET NX` idempotency; high-risk waits for approval.
- **P1-T10** Lead schema + persist-before-AI capture (LFR-CAP-001..004, LBR-5.1) — persist THEN enqueue AI; AI failure preserves the lead.
- **P1-T11** Duplicates, AI analysis, deterministic routing (LFR-DUP-001, LFR-AI-001/002/003, LFR-ROUTE-001).
- **P1-T12** Messaging, tasks, corrections, privacy (LFR-MSG-001/002, LFR-TASK-001, LFR-DASH-004, LFR-PRIV-001, LFR-SEC-001).
- **P1-T13** Audit, notifications, observability, retention (FR-AUD-001/002, FR-NOTIF-001, FR-OBS-001, FR-DATA-002) — **append-only via MySQL BEFORE UPDATE/DELETE triggers**; test that `UPDATE` throws.
- **P1-T14** Assessment module + BAAF scoring (FR-ASMT-001/002, BAAF-001..006).
- **P1-T15** Dashboard + WCAG 2.2 AA (FR-DASH-001/002, LFR-DASH-*, A11Y-001..006) — **manual a11y pass is mandatory** (axe-core alone insufficient).

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
- **Migrations idempotent:** `CREATE TABLE IF NOT EXISTS`, inline indexes, guarded seed `INSERT`s, `DROP ... IF EXISTS`. `TestCase` re-applies all `migrations/*.sql` before every test.
- **gitleaks** runs from HOST (not container); `.gitleaks.toml` allowlists `vendor/`, `*.phar`, lockfiles, `sbom.xml` — real source is still scanned. An empty bind mount false-passes; confirm non-zero byte scan.

## 6. Critical disciplines (learned the hard way — do not repeat)
- **Never trust last session's green.** Before claiming green or starting, **re-run the FULL gate including `composer audit`** — advisories appear over time (a phpcs CVE surfaced only because `ci-local.sh` was re-run). After any major dep bump, re-verify the phpcs ruleset still passes.
- **Subagent summaries are advisory, not ground truth.** Async subagents hit HTTP 429/524 and **time out before committing** (work lands untracked), or report **stale state** from a concurrent sibling's mid-flight phase. Always re-verify repo state with real `git`/`phpunit` commands and finish/commit yourself when an agent dies.
- **Verify claims with real tool output**, never summarize from memory. Produce ad-hoc verification via a temp script named with the `hermes-verify-` prefix in `%TEMP%`, run it, report `VERIFY_EXIT`, then delete it.
- **CRLF:** `.gitattributes` is committed — do not remove it. `.sh` files must be LF in-container.
- **`mysql-client`** in the Dockerfile (binary `mysql`), NOT `default-mysql-client`.

## 7. OPEN QUESTIONS — resolve BEFORE / early in Phase 1 (plan §7)
The plan says these MUST be settled before/early in Phase 1. **Surface them to the user; do not silently assume:**
1. (Resolved in plan) Deployment: cloud + local, **local-first default**, cloud fallback; AC-006 proven during Phase 1.
2. **RBAC vs ABAC for v1** (FR-TEN-003) — plan recommends **RBAC for MVP**; needs owner sign-off. Decide before P1-T4.
3. **SLA numbers + performance budgets** (NFR Table 5) — needed to make the release-gate objective.
4. **Pen-test window + authorizing party + environment** (SEC-009, SFR-AUTH-001) — book before Phase 1 exit; it's a release gate.
5. **Standards register cadence** — owner + next review date; fix AISVS→ASVS 5.0 wording then.
6. (Resolved) Repo on `C:`; no GitHub remote.
7. **First tenant's data classes** — drives LFR-AI-002 redaction config.
- **GitHub-dependent items required before Phase 1 EXIT (not Phase 0):** (a) Actions running, (b) SEC-008 branch protection on `main`. If still no remote at P1 exit, flag as OPEN ITEMS, not silent skips.

## 8. Stop condition
Reach the **Phase 1 Exit Gate** (plan §995): suite green in BOTH cloud and local-Ollama configs (AC-006); AC-001/002/003 proven by negative tests; lead MVP 12-step E2E in one integration test; 10 Lead FRD Table 4 cases pass; axe-core + manual a11y; CI green + SBOM + no critical findings; threat model updated for AI gateway + tool egress; traceability matrix complete. **Do not drift into Phase 2+.** Update `docs/HANDOFF.md` and `docs/TRACEABILITY.md` for the next session.

## 9. First concrete step
Boot the stack (§2), confirm phpunit is green, then ask the user to resolve Open Question #2 (RBAC vs ABAC) before dispatching P1-T1. Report the boot result with real output before doing anything else.
