# Aiwebscapes Platform — Session Handoff (Phase 0 → Phase 1)

**Prepared:** 2026-08-05 (end of Phase 0 execution session); **refreshed 2026-08-07** through P1-T10
**Repo:** `C:\Users\CTYea\dev\aiwebscapes-platform` (branch `main`; T1–T11 pushed to origin as of 2026-08-07; working tree clean)
**Plan:** `C:\Users\CTYea\.hermes\plans\2026-08-05_100000-aiwebscapes-production-system-plan.md` (1,180 lines, source of truth)
**Read this file first** in the next session, then the plan. It captures live state the plan does not.

---

## 0. TL;DR for the next session

- **Phase 0 is COMPLETE and green.** All 13 planned tasks done, both exit gates passed. 15 commits on `main`, working tree clean (`vendor/` + `.phpunit.cache/` untracked only).
- **Two infra fixes were applied TODAY (last commit `6301283`)** — read §3. Both matter for your first `phpunit` run.
- **Your first action:** `cd /c/Users/CTYea/dev/aiwebscapes-platform && docker compose up -d` (brings the stack with the new restart policy), wait for `db` healthy, then `docker compose exec -T app vendor/bin/phpunit`.
- **Phase 1 is the next block** (P1-T1…P1-T15, multi-tenant core + lead MVP). It has **5 open questions the plan says must be resolved before/early in Phase 1** — see §6.
- **Reusable skill exists:** `php-docker-tested-build` (load it with `skill_view(name='php-docker-tested-build')`). It holds every environment gotcha. Memory has the build facts too.
- **SECURITY-FIRST is the standing discipline (owner directive, 2026-08-07):** every Phase-1 task — design, review, and re-verify — treats security as the PRIMARY axis, not a checklist item. Load-bearing guarantees: **AC-001** (tenant isolation — no unscoped client query), **AC-002** (allowlists not denylists), **AC-003** (a model output that fails schema/policy produces NO external side effect), **FR-AI-006** (AI cannot autonomously authorize high-impact actions), **SEC-005** (deny-by-default), **SEC-010 / SFR-AI-002** (prompt-injection defense; untrusted content is DATA, never instructions), and the **SSRF egress guard** (P1-T8). Rule: when a plan/code skeleton conflicts with a security guarantee already built, reconcile TOWARD the guarantee and flag the deviation — never silently follow the buggy skeleton. Subagent summaries are ADVISORY; always re-verify with real git/phpunit on an ISOLATED TEST_DB_DSN before marking done.

---

## 1. What is built (Phase 0 deliverables)

| Commit | Task | Evidence |
|---|---|---|
| `b6dd7a7` | M1 baseline import | `legacy/` byte-identical, 8 PHP + 4 other files |
| `67b14c9` | M2 Docker env | PHP 8.3.33 + MySQL 8.4.11 + Redis 7 |
| `580af96` | M2 fix | `mysql-client` image (not `default-mysql-client`) |
| `e1f58f2` | M3 Composer/PHPUnit | PHPUnit 11.5.56 harness |
| `82e00b9` | M3 strict gate | php 8.3 pin, composer scripts, strict phpunit.xml |
| `f24b40c` | M4 TestCase base | real-MySQL rollback isolation, **mutation-tested** |
| `a886a0b` | P0-T1 | PSR-12 + PHPStan config; 9 files' copyright corrected (`© AI WebScapes 2026`) |
| `63966cd` | P0-T1 | `.gitattributes` forces LF (CRLF gotcha) |
| `9ce0e38` | P0-T2 | `src/Config/Secrets.php` + `MissingSecretException.php`; legacy `config/app.php` fail-closed |
| `b2330a2` | P0-T3 | `src/Security/RateLimiter.php` (Redis, LFR-CAP-003); old `$_SESSION` limiter gone |
| `27e06ed` | M4 review C2 | DDL-leak loud-failure guard in `tests/TestCase.php` |
| `faa4b25` | P0-T4 | `migrations/000_baseline.sql` (idempotent) + `scripts/{migrate,backup,restore}.php`; `tests/Infra/BackupRestoreTest.php` |
| `d528f0e` | P0-T5 | `scripts/ci-local.sh` (6/6 gates) + `.github/workflows/ci.yml` + `.gitleaks.toml` + SBOM |
| `9b34858` | P0-T7 | `docs/INCIDENT_RESPONSE.md` (BR-12.6 runbook) |
| `0ac2fdd` | P0-T6 | `docs/THREAT_MODEL.md` + `docs/adr/0001-modular-monolith.md` |
| `6301283` | **TODAY fix** | `restart: unless-stopped` + phpcs 4.0.4 (CVE-2026-67434) |

**Current gate status (verified 2026-08-07, after P1-T11 re-verify on isolated DB):** phpunit `OK (161 tests, 391 assertions)` · phpstan L8 `[OK] No errors` · phpcs 0. Phase-1 tasks complete: **T1–T11** (T12–T15 remain). Each task verified on its own isolated `TEST_DB_DSN`.

---

## 2. Environment ground truth (do NOT re-derive)

- **Host:** Windows 10. `terminal` tool = **bash (git-bash/MSYS)**, NOT PowerShell. POSIX paths.
- **No PHP/Composer/mysql client on the host.** EVERYTHING via `docker compose exec -T app ...` (always `-T`).
- **Stack:** `app` (php:8.3-cli, `sleep infinity`, bind mount `.:/app`), `db` (mysql:8, port `3307:3306`), `redis` (7-alpine). Project name `aiwebscapes-platform`.
  - DSNs: `DB_DSN=mysql:host=db;dbname=aiwebscapes`, `TEST_DB_DSN=mysql:host=db;dbname=aiwebscapes_test`, `REDIS_DSN=tcp://redis:6379`.
  - `AI_LOCAL_BASE_URL=http://host.docker.internal:11434/v1` (Ollama on Windows host, GTX 1660 Ti, 6GB).
- **Repo MUST stay on `C:`** — `E:` is removable exFAT, Docker mounts it silently empty.
- **GitHub remote EXISTS** — `origin = https://github.com/todyeag6/ai-workspace.git` (since 2026-08-06). Pushes are the OWNER's call: do NOT `git push`/`force-push` without an explicit per-occasion instruction. CI is proven by `scripts/ci-local.sh` (see §9); the remote Actions run is tier-limited on a Free private repo.
- **gitleaks** runs from HOST: `docker run --rm -v "$(pwd -W)":/repo ghcr.io/gitleaks/gitleaks:latest dir /repo --redact --no-banner --config=/repo/.gitleaks.toml` (exit 1=leaks). An empty mount false-passes — confirm non-zero byte scan.
- **Requirement text** lives in `C:\Users\CTYea\.hermes\_awsx_extract/*.txt` (7 files). The plan's Traceability Matrix seeds **168 requirements**.

---

## 3. TWO FIXES APPLIED TODAY — read before your first run

### 3.1 `compose.yaml`: `restart: unless-stopped` (commit `6301283`)
**Problem the user reported:** the `db` and `redis` containers exit (code 255) **daily** and never come back, so `app` can't resolve `db`/`redis` and **phpunit goes RED with `getaddrinfo for db/redis failed`**. This is a recurring false alarm, not a code regression.
**Fix:** added `restart: unless-stopped` to `app`, `db`, `redis`. After this commit, a `docker compose up -d` recreates the containers with the policy and they self-heal on host reboot/exit.
**Your first run:** `docker compose up -d` (no rebuild), wait ~30s for `db` healthy, then run gates. If you see `getaddrinfo failed`, the containers are down — `docker start aiwebscapes-platform-db-1 aiwebscapes-platform-redis-1` (or just `docker compose up -d`).

### 3.2 phpcs CVE bump: `squizlabs/php_codesniffer` 3.13.x → 4.0.4 (commit `6301283`)
**Problem:** `composer audit` flagged **CVE-2026-67434** (OS command injection) in phpcs <3.13.6. Composer resolved to **4.0.4** (a major bump). `phpcs.xml` ruleset is compatible with 4.x (verified: phpcs 0 errors). `composer.lock` updated.
**Note:** this is a DEV dependency only (not in production runtime), so blast radius is low.

---

## 4. How to run (verified commands)

```bash
cd /c/Users/CTYea/dev/aiwebscapes-platform
docker compose up -d                      # bring stack (applies restart policy)
# wait for: docker ps | grep aiwebscapes-platform   (db = healthy)

docker compose exec -T app vendor/bin/phpunit                              # suite
docker compose exec -T app vendor/bin/phpstan analyse --no-progress        # L8
docker compose exec -T app vendor/bin/phpcs --standard=phpcs.xml src tests # PSR-12
bash scripts/ci-local.sh                  # all 6 gates (run from any CWD)
docker compose exec -T app php scripts/migrate.php --dsn="$TEST_DB_DSN"    # re-apply migrations
```

**Migrations are idempotent** — `TestCase` re-applies `migrations/*.sql` before every test; `schema_migrations` ledger dedupes. New migration files: `001_*.sql` … `007_*.sql` (Phase 1 adds these).

---

## 5. Reusable assets created this session

- **Skill `php-docker-tested-build`** — full Windows-MSYS PHP/Docker TDD runbook (CRLF, `mysql-client`, gitleaks allowlist, migration idempotency, DDL-leak guard, async-subagent resilience). Load before Phase 1 work.
- **Skill `subagent-driven-development`** — patched with a "Resilience: Timeouts & Stale Async Summaries" section (subagents die on HTTP 429/524 before committing; report stale state from concurrent siblings — re-verify with real `git`/`phpunit`).
- **Skill `database-test-isolation`** — patched with the DDL-leak loud guard + migration idempotency contract.
- **Memory** — has: platform Docker stack facts, migration idempotency, gitleaks discipline, and the async-subagent resilience lesson.
- **`.gitleaks.toml`** allowlists `vendor/`, `*.phar`, lockfiles, `sbom.xml` (real source still scanned). Validate the scanner with a REAL planted key, not the allowlisted AWS doc key.

**TDD iron law enforced all session:** no production code without a failing test first; every task had spec-compliance + code-quality review.

---

## 6. Phase 1 — what's next, and the 5 OPEN QUESTIONS

Phase 1 = **Multi-Tenant Core + Lead Follow-Up MVP**, 15 tasks (P1-T1…P1-T15). The plan is explicit: **"Tenancy first. Do not build features before P1-T4 passes — every later requirement inherits AC-001."** Use `subagent-driven-development` exactly as Phase 0 did.

**Critical open questions the plan says MUST be resolved before/early in Phase 1** (plan §7) — do NOT silently assume:

1. ~~Deployment model~~ — RESOLVED in plan: both cloud + local, **local-first default**, cloud fallback; AC-006 proven during Phase 1 (not deferred).
2. ~~**RBAC vs ABAC for v1** (FR-TEN-003)~~ — RESOLVED in plan: **RBAC for MVP**, ABAC later. Owner sign-off recorded; P1-T4 built authz on RBAC.
3. **SLA numbers + performance budgets** (NFR Table 5 "agreed per client") — needed to make the release-gate item 7 objective.
4. **Pen-test window, authorizing party, environment** (SEC-009, SFR-AUTH-001) — **book before Phase 1 exit.** It's a release gate, not a surprise.
5. **Standards register cadence** — confirm owner + next review date. (NOTE: the Standards_Research_Register.txt already correctly lists BOTH "OWASP ASVS 5.0.x" AND "OWASP AISVS" — the earlier handoff note suggesting an "AISVS→ASVS" fix was WRONG; no change needed.)
6. ~~Repo location~~ — RESOLVED: `C:\Users\CTYea\dev\aiwebscapes-platform` on `C:`. GitHub not set up.
7. **First tenant's data classes** — drives LFR-AI-002 redaction config.

**Two items that are OPEN until a GitHub remote exists (plan §7.6) — required before the PHASE 1 exit gate, not Phase 0:**
- (a) GitHub Actions actually running (`.github/workflows/ci.yml` is committed and ready, but needs a remote).
- (b) **SEC-008 branch protection** on `main`.

> If the user still has no GitHub remote at Phase 1 exit, the plan considers these open items — flag them explicitly rather than silently skipping.

### Phase 1 task map (from plan, verbatim IDs)
- **P1-T1** Tenant + identity schema (FR-TEN-001, FR-IDENT-*) — `migrations/001_tenants_identity.sql`; legacy `users.email UNIQUE` → `(tenant_id,email)`. ✅ **DONE** (`cf00ca8`)
- **P1-T2** Password hasher (FR-IDENT-002) — `src/Identity/PasswordHasher.php`, **argon2id**, rehash-on-upgrade. ✅ **DONE**
- **P1-T3** TenantScope + repository base (FR-TEN-002, AC-001) — unscoped queries structurally impossible; PHPStan rule forbids raw `->query()`/`->exec()` on client tables outside `TenantRepository`. ✅ **DONE** (`3a69497`+`4f82f86`+`cadaa94`)
- **P1-T4** Auth service + tenant authz middleware (FR-IDENT-001/003/004, SEC-005, AC-001) — **deny-by-default**; 403 for both "wrong tenant" and "not found" (no ID enumeration). ✅ **DONE** (`88d4095`)
- **P1-T5** Agent registry (FR-AGENT-001/002/003) — disabled-by-default, versioning. ✅ **DONE** (`90ccdb3`, pushed to origin)
- **P1-T6** AI Gateway + schema validation (FR-AI-002/003, AC-003) — invalid output → `disposition='review'`, never a side effect. ✅ **DONE** (`297e915`, pushed)
- **P1-T7** Local + cloud adapters, local-first router, injection filter (FR-AI-001/004/005/006) — **never `gemma4:12b`** on auto (on-demand only); default `qwen3:4b`, quality `hermes3:8b`. ✅ **DONE** (`db2be7e`, pushed)
- **P1-T7.5** Single-resident model policy + 8192 context ceiling (FR-AI-001/004) — `hermes3:8b` prevalent; `LocalModelResolver`; ceiling enforced fail-safe. ✅ **DONE** (`1c25f00`, pushed)
- **P1-T8** Tool/Connector Gateway (FR-TOOL-001/002/003, AC-002) — allowlists not denylists; **DNS-free SSRF** egress guard (blocks 169.254.169.254 metadata, RFC1918, loopback; no gethostbyname). ✅ **DONE** (`a9a4b3b`, pushed)
- **P1-T9** Workflow orchestrator (FR-ORCH-001/002/003) — Redis `SET NX` idempotency (effect-free replay); high-risk waits for human approval (FR-AI-006 at orchestration level). ✅ **DONE** (`1aa7db3`, pushed)
- **P1-T10** Lead schema + persist-before-AI capture (LFR-CAP-001..004, LBR-5.1) — **public endpoint**: honeypot accepts-not-persists; throttle **fail-closed** (429); persist-then-enqueue-AI; AI failure → lead stays `Review`; all leads tables tenant-scoped (AC-001). ✅ **DONE** (`5dc7b63`, pushed)
- **P1-T11** Duplicates, AI analysis, routing (LFR-DUP-001, LFR-AI-001/002/003, LFR-ROUTE-001) — duplicate **linked not overwritten** + re-analysis appends new version; **LFR-AI-002 allow-list redaction** (no PII/SSN reaches model); **deterministic rule overrides AI** (LFR-ROUTE-001); low confidence → `Review`. ✅ **DONE** (`be3855e`, pushed)
- **P1-T12** Messaging, tasks, corrections, privacy (LFR-MSG-001/002, LFR-TASK-001, LFR-DASH-004, LFR-PRIV-001, LFR-SEC-001).
- **P1-T13** Audit, notifications, observability, retention (FR-AUD-001/002, FR-NOTIF-001, FR-OBS-001, FR-DATA-002) — **append-only via MySQL BEFORE UPDATE/DELETE triggers** (test that `UPDATE` throws).
- **P1-T14** Assessment module + BAAF scoring (FR-ASMT-001/002, BAAF-001..006).
- **P1-T15** Dashboard + WCAG 2.2 AA (FR-DASH-001/002, LFR-DASH-*, A11Y-001..006) — **manual a11y pass is mandatory** (axe-core alone insufficient).

### Standards-baseline coverage (approved v1.0 register — reconciliation note)
The Aiwebscapes **Approved Baseline v1.0** (`C:\Users\CTYea\awsx_docs\`, authoritative `.docx`; PDFs are duplicates, never read) maps to the OWASP/NIST controls below. Phase-1 implementation to date exercises these load-bearing guarantees, each proven by negative tests on an isolated DB:

| Baseline control | Where enforced in code (verified) |
|---|---|
| **OWASP ASVS 5.0.x** (V4/V5/V11 authn/authz) | `PasswordHasher` (argon2id, P1-T2); `AuthService` deny-by-default 403 (P1-T4); `ActionAuthority.authorizeTransaction()` refuses high/critical (P1-T7/P1-T9) |
| **OWASP AISVS** (AI security) | `InjectionFilter` (structural untrusted-content quarantine, P1-T7); `ModelRouter` local-first (P1-T7); `LocalModelResolver` allowlist + 8192 ceiling (P1-T7.5) |
| **OWASP Top 10:2025 / API Top 10:2023** (SSRF, broken authz) | `ToolGateway` DNS-free SSRF block (169.254.169.254/RFC1918/loopback, P1-T8); `ToolGateway` allowlist-only (AC-002, P1-T8); tenant scoping `TenantScope` (AC-001, P1-T3) |
| **OWASP GenAI/LLM Top 10** (prompt injection, excessive agency) | `InjectionFilter` (SEC-010/SFR-AI-002, P1-T7); `ActionAuthority` no autonomous high-impact (FR-AI-006, P1-T7/P1-T9); `LeadService` public-endpoint fail-closed throttle + honeypot + persist-before-AI (LBR-5.1, P1-T10) |
| **NIST AI RMF 1.0 + GenAI Profile** | `AIGateway` invalid-output → `disposition='review'`, never a side effect (AC-003, P1-T6); `Orchestrator` effect-free replay + compensating actions (P1-T9) |
| **NIST SSDF 1.1 / CSF 2.0** | `ci-local.sh` 6/6 gates; gitleaks + SBOM; idempotent migrations; PHPStan L8 with `NoUnscopedClientQueryRule` |
| **WCAG 2.2 AA** | P1-T15 (pending) — dashboard + manual a11y pass |

> Reconciliation rule (owner): external-facing claims (deck/proposal/marketing) must be reconciled to this baseline, not over-claimed. P1-T1…T10 are implementation-complete and security-reviewed; T11–T15 remain before the Phase-1 exit gate.

**Phase 1 Exit Gate** (plan §995): suite green in BOTH cloud and local-Ollama configs (AC-006); AC-001/002/003 proven by negative tests; lead MVP 12-step E2E; 10 Lead FRD Table 4 cases pass; axe-core + manual a11y; CI green + SBOM + no critical findings; threat model updated for AI gateway + tool egress; traceability matrix complete.

---

## 7. Gotchas log (cost real time — avoid re-learning)

1. **CRLF:** host `core.autocrlf=true`; without `.gitattributes`, committed `.sh` check out CRLF in-container → `\r: command not found`. Fixed in `63966cd`. Don't remove `.gitattributes`.
2. **`mysql-client` not `default-mysql-client`** in the Dockerfile — the plan text says the latter; the binary the code calls is `mysql`.
3. **Two classes per file** fails PSR-1 AND breaks PSR-4 autoload → split files (PSR-1 violation is not auto-fixable).
4. **`require` is a valid PHP 8 method name** — `Secrets::require()` is fine.
5. **gitleaks vendor phar false positives** — `.gitleaks.toml` allowlist in place. Real source still scanned.
6. **Async subagents time out (HTTP 429/524) before committing** or report stale state — re-verify with real `git`/`phpunit`, then commit yourself. Subagent summaries are advisory.
7. **Daily container exit** — fixed by `restart: unless-stopped` (§3.1). If phpunit REDs with `getaddrinfo failed`, the stack is down, not the code. NOTE: MySQL DATA lives in a Docker VOLUME that survives container restart — stray `aiwebscapes_*_iso`/`*_verify` test DBs are NOT auto-removed by a restart; they persist until explicitly `DROP`ped (each DROP is a consent-gated SQL action). Don't claim they self-clean.
8. **phpcs major bump** to 4.0.4 — ruleset compatible; re-run `composer audit` in CI to keep the gate honest.

---

## 8. Scope discipline for the next session

- **Stop at the Phase 1 exit gate** (plan §8: "Do not begin Phase 1 feature work until the P0 exit gate is green" — that's done; analogously, stop at P1 gate, don't drift into Phase 2).
- Phases 2–5 (Productization, Defensive Security Agent, Local/Hybrid Toolkit, Scale) are out of scope until Phase 1 is gated.
- Keep the traceability matrix (`docs/TRACEABILITY.md`, planned) updated: every Phase-1 requirement row needs a named passing test before the P1 gate.

---

## 9. GitHub CI + branch protection — REALITY (verified 2026-08-06)

The remote **exists**: `origin = https://github.com/todyeag6/ai-workspace.git`
(user created it; first commit `5dfdc84`). `main` tracks `origin/main`. Code is
pushed (`9eb9fa1` is the latest on the remote as of this note).

### 9.1 CI workflow IS active, but the runner is starved
- `.github/workflows/ci.yml` is committed and runs the **same six gates** as
  `scripts/ci-local.sh` on a GitHub-hosted runner (push + PR triggers).
- A **critical fix** landed in `9eb9fa1`: the MySQL service was mislabeled
  `mysql` while the PHP DSNs connect to host `db`, and relied on a fragile
  `echo 127.0.0.1 db redis | sudo tee /etc/hosts` step. Per the **official
  GitHub Actions docs** ("the hostname of the service container is the label
  you configure"), the service is now named `db` (matching the DSN) and the
  `/etc/hosts` hack is gone. The pre-fix runs (`800e3fd`, `5dfdc848`) failed
  with run=failure / job=cancelled / 0 steps / no logs — consistent with the
  service being unreachable.
- **The fix is validated locally**: `bash scripts/ci-local.sh` on `9eb9fa1`
  returns `ALL LOCAL CI GATES PASSED (6/6)` — 52 tests, 111 assertions. The
  workflow mirrors these exact checks, so gate *correctness* is proven locally.
- **GitHub run `31124162872` (head `9eb9fa1`) is stuck `queued`** — NOT failed.
  On a **free private repo, GitHub allocates runners sparsely**; runs sit in
  queue for many minutes before (if) a runner picks them up. No completion
  email arrives while queued. This is a **plan-tier scheduler artifact, not a
  code defect.** Treat `ci-local.sh` as the authoritative CI proof; the remote
  run is a nice-to-have that the free tier may never schedule promptly.

### 9.2 Branch protection (SEC-008) is BLOCKED by the plan tier
- Both the **legacy branch-protection API** and the **rulesets API** return
  `403 "Upgrade to GitHub Pro or make this repository public to enable this
  feature."` for this private Free repo.
- Confirmed against **official GitHub docs**: protected branches / rulesets are
  available in **public repos**, and in **private repos only with GitHub Pro,
  Team, or Enterprise**. GitHub Free (private) gets them for public repos only.
- Therefore SEC-008 (require PR + review + status check before merge, block
  force-push/delete) **cannot be enabled as-is**. Options, per the owner:
  1. Make the repo **public** (protection works free) — risky for proprietary code.
  2. **Upgrade to GitHub Pro** ($4/mo) — keeps it private AND unlocks rulesets
     (the recommended, more granular enforcement).
  3. **Stay private + free** — CI still runs on push/PR, but the *merge gate*
     cannot be enforced. Document SEC-008 as OPEN (blocked by plan tier), not
     silently skipped.
- Decision as of 2026-08-06: **stay private + free**; owner pushes their own.
  SEC-008 remains an OPEN item in the Phase-1 exit gate, recorded here.

### 9.3 What this means for the exit gate
- "GitHub Actions running" — SATISFIED in principle (workflow active + local
  gate green); the remote run's completion is tier-limited.
- "SEC-008 branch protection" — OPEN (tier-blocked, documented above).
- Neither blocks local development or the local `ci-local.sh` gate, which is
  the source of truth for "are the six gates green."

---

*This handoff is a living snapshot. The authoritative plan is the `.hermes/plans/...` file; this doc captures live repo state the plan cannot.

---

## 10. P1-T15 — Dashboard + WCAG 2.2 AA (DONE 2026-08-08, local-only)

**Commit:** `feat(dashboard): FR-DASH-001/002 + LFR-DASH-* + A11Y-001..006` (pending owner push).
**Files:** `migrations/009_dashboard.sql`, `src/Dashboard/{DashboardRepository,DashboardView,DashboardController}.php`, `public/index.php`, `tests/Dashboard/{PipelineTest,AccessibilityTest}.php`.

### Gate results (isolated DB `TEST_DB_DSN`)
- `phpunit` — **OK (201 tests, 524 assertions)** (baseline 191/489 → +10 tests/+35 assertions from T15).
- `phpstan analyse` — **[OK] No errors** (L8).
- `phpcs --standard=phpcs.xml src tests public` — **0 errors** (only pre-existing line-length warnings; no `LineLength` rule configured).
- `composer audit` — **no security advisories**.
- `gitleaks` — **no leaks**.
- **axe-core 4.13.0** against the rendered `/dashboard` (WCAG2A/AA/2.2AA tag set) — **0 violations**.
- **Manual a11y pass (A11Y-006) recorded** — lang/title/single-h1/landmarks ✓; skip link + native controls + `:focus-visible` 3px outline + no autofocus trap ✓; form `aria-invalid`+`aria-describedby`→`role="alert"` ✓; status text+icon (not colour) ✓; contrast ≥4.5:1 (`#1a1a1a`/white ≈17:1, link `#0b5cab` ≈5.9:1, error `#b00020` ≈5.9:1) ✓; `prefers-reduced-motion` ✓.

### Mutation-proof of the accessibility tests
Removing `aria-invalid="true"` + `role="alert"` from `leadFormHtml()` made
`AccessibilityTest::test_form_errors_programmatically_determinable` fail — the
automated assertions are not vacuous (verified, then reverted).

### Deviations from the plan's T15 skeleton (reconciled toward the built guarantee)
1. **Pipeline = 5 states**, not the plan's 10. `migrations/005_leads.sql` defines
   `leads.status` ENUM(`New,Review,Qualified,Disqualified,Converted`); no prior
   task built the 10-state model. T15 asserts the real 5 and does not mutate the
   domain model. See `docs/TRACEABILITY.md` §Deviance.
2. **No web kernel** (Slim/Twig/`public/index.php` absent in the built platform).
   Followed the existing array-in/out controller convention; `public/index.php`
   is a minimal, tenant-fixed front controller added only for the axe served gate.
3. **`message_deliveries` had no outcome signal.** `migrations/009_dashboard.sql`
   adds idempotent `status`+`error` columns so `failedDeliveries()` reads real data.

### Stray DBs from T15 verification
Several `*_t15*` / `*_t15b*` / `*_t15c*` / `*_t15d*` / `*_t15full*` / `*_t15gate*`
isolation DBs were created during verification (CREATE-only, never dropped —
Docker volume persists). Harmless; drop on owner consent like the T13/T14 strays.
The dev `aiwebscapes` DB was migrated (009 applied) so the served dashboard is real.

### Phase-1 exit gate — remaining owner actions
- Push T13 (`e3cfc07`) + T14 (`b9eefd1`) + T15 (this commit).
- Book pen-test (SEC-009 / SFR-AUTH-001); supply SLA/perf budgets (NFR Table 5).
- SEC-008 branch protection stays OPEN (GitHub Free private tier — documented, not skipped).

---

## 11. P2-T1 — Evaluation harness + activation gate (DONE 2026-08-08, local-only, NOT pushed)

**Commit:** `feat(eval): P2-T1 golden-prompt harness + eval-gated activation (FR-AGENT-003)` (pending owner push).
**Files:** `config/eval/{KPI_THRESHOLDS,GOLDEN_SUITE}.php`, `src/Eval/{EvalResult,EvalHarness,EvalMeasurementSource,GoldenSuiteSource}.php`, `src/Agents/{AgentEvaluationRepository,EvaluationReleaseGate}.php`, `migrations/010_agent_eval.sql`, `tests/Eval/EvalHarnessTest.php`, `tests/Agents/AgentRegistryTest.php` (+ registry wiring).

### Gate results (isolated DB `TEST_DB_DSN`)
- `phpunit` — **OK (207 tests, 546 assertions)** (baseline 201/524 → +6 tests/+22 assertions from P2-T1).
- `phpstan analyse` — **[OK] No errors**. `phpcs --standard=phpcs.xml src tests` — **0 errors** (pre-existing line-length warnings only).

### What P2-T1 delivers (and what was already there)
- The agent **versioning/registry spine** (AgentRegistry, AgentVersion, FR-AGENT-002/003 immutable versions, disabled-by-default) was already built in P1-T5 and is tested. P2-T1 adds the missing half: the **evaluation harness + the activation gate that consumes its verdict**.
- `EvalHarness` runs the golden suite through the EXISTING `AIGateway` (schema-validated, side-effect-free by construction — holds only a gateway + measurement source, no PDO/mailer/tool-gateway → AC-003 compliant). It compares the BRD Table 4 KPI dimensions against thresholds and returns a verdict.
- `EvaluationReleaseGate` records the verdict in an **append-only `agent_evaluations` ledger** (migration 010; preserves the immutable-versions guarantee) and then calls `AgentRegistry::activate(evalPassed)`. The registry never computes the verdict itself (its own design rule — a gate that could open itself is not a gate).

### BASELINE GROUNDING DISCREPANCY — flagged, not papered over
- The plan says "KPI thresholds from BRD Table 5". **The approved BRD specifies NO numeric KPI targets**, and BRD Table 5 is *Risk → Required Treatment*, not numbers. The 6 KPI **dimensions** (task success, groundedness, human override rate, escalation rate, harmful/invalid output rate, model cost per completed business outcome) come from **BRD Table 4** ("AI quality" measures).
- Therefore `config/eval/KPI_THRESHOLDS.php` carries explicit **PROPOSED** defaults, flagged "owner to ratify" — not fabricated production numbers. They are change-controlled in one file so a ratifier edits thresholds, not the harness.
- Golden-suite output schemas use **scalar leaves only**: `SchemaValidator` (P1-T6) rejects `object`/`array` type-names by design, accepting nested objects with scalar leaves only. Documented in `GOLDEN_SUITE.php`.

### Harness design decision (owner-ratified via clarify)
- **Pure unit harness**: golden inputs → injected fake `ModelAdapter` → asserted outputs. Deterministic, CI-fast, no real model/network. A real-model runner (optional, out of scope) would implement `EvalMeasurementSource` over live runs behind the same interface.

### Key tests (mutation/regression proof)
- `EvalHarnessTest::test_closing_one_threshold_fails_the_gate` — weakening a measured KPI fails the whole run (gate is not vacuous).
- `EvalHarnessTest::test_schema_invalid_output_is_harmful_and_fails` — invalid output forces `harmful_invalid_rate=1.0` → fails (AC-003 fail-safe path exercised).
- `AgentRegistryTest::test_evaluation_failed_records_run_and_blocks_activation` — failing eval records the row AND leaves the agent disabled (audit trail + refusal proven together).

### Phase 2 remaining (per plan)
P2-T2 connectors + model routing · P2-T3 workflow builder UI + reporting · P2-T4 managed-ops substrate · P2-T5 packaged vertical offering.

---

## 12. P2-T2 — Reusable connectors + cost-aware model routing (DONE 2026-08-08, local-only, NOT pushed)

**Commit:** `feat(connectors): P2-T2 connector SDK + cost-aware routing (FR-TOOL-003, FR-AI-001)` (pending owner push).
**Files:** `src/AI/ModelRouter.php` (cost dimension), `src/Connectors/{ConnectorSpec,ConnectorClient,Http/Crm/EmailConnectorClient,ConnectorRegistry,ConnectorExecutor}.php`, `migrations/011_connector_bindings.sql`, `tests/AI/ModelRouterCostTest.php`, `tests/Connectors/ConnectorExecutorTest.php`.

### Gate results (isolated DB `TEST_DB_DSN`)
- `phpunit` — **OK (218 tests, 565 assertions)** (prior 207/546 → +11 tests / +19 assertions from P2-T2).
- `phpstan analyse` — **[OK] No errors**. `phpcs --standard=phpcs.xml src tests` — **0 errors** (pre-existing line-length warnings only).

### What P2-T2 delivers (and what was already there)
- **Already built in P1** (surveyed, not re-plumbed): `tools`/`connectors` catalogue (migration 003), the P1-T8 `ToolGateway` decision engine (allowlist + SSRF + egress + high-impact `ActionAuthority` — it DECIDES, performs no egress), and the full model-routing spine (`ModelRouter`, `LocalModelResolver`, `CloudAdapter`/`LocalAdapter`). P2-T2 adds the two genuine gaps the plan names.
- **Cost-aware routing (FR-AI-001, "cost/latency/quality"):** `ModelRouter::select()` gained an optional cost dimension (`costCeilingCents`, `localCostCents`, `cloudCostCents`). Local-first is preserved; cloud is chosen only when local is unreachable OR local exceeds the ceiling and cloud clears it; when nothing fits the budget+ceiling the call goes to `review`. A null ceiling keeps the pre-P2-T2 behaviour for every existing caller (AdapterTest still passes).
- **Connector execution SDK (FR-TOOL-003, "connector SDK on the P1-T8 gateway"):** the `connectors` table existed but nothing executed an approved tool call through it. Added `ConnectorSpec` (vetted destination, never model-supplied), `ConnectorClient` interface + `Http`/`Crm`/`Email` clients (injected transport → unit-testable, no socket), `ConnectorRegistry` (resolves tool→connector from the catalogue via new `connector_bindings` table, migration 011), and `ConnectorExecutor` — the **actor** that takes the gateway's decision record and performs the single egress. Decider (`ToolGateway`) ≠ actor (`ConnectorExecutor`), preserving the AC-003 split. The actor performs NO allowlist/SSRF/egress re-check.

### Design decisions / faithful-to-built
- **Migration 011** follows the project idempotency contract: `CREATE TABLE IF NOT EXISTS` + `INSERT IGNORE` only, no ALTER/DROP. It seeds the `connectors` rows (003 created the table but seeded none) and the `connector_bindings` (tool→connector) the SDK needs.
- **No silent default connector type:** `ConnectorExecutor` throws if no client handles the resolved type — an unknown type is refused, not swallowed.
- **Empty-key bug fixed during TDD:** `is_string($params['x'] ?? '')` is `true` for a missing key (empty string is a string), which returned the undefined key. Switched to explicit non-empty checks across all three clients (mutation-style catch during the run).

### Key tests (regression / non-vacuous)
- `ModelRouterCostTest::test_review_when_both_runtimes_exceed_cost_ceiling` — over-ceiling on both → `review`, not `local`.
- `ModelRouterCostTest::test_cost_ignored_when_no_ceiling_supplied` — backward-compatible pre-P2-T2 path pinned.
- `ConnectorExecutorTest::test_executor_refuses_without_gateway_decision` — actor never runs an unauthorised record.
- `ConnectorExecutorTest::test_unknown_connector_type_has_no_silent_default` — missing client → exception.
- `ConnectorExecutorTest::test_gateway_still_refuses_unlisted_tool_before_execution` — decider still guards the actor.

### Phase 2 remaining (per plan)
P2-T3 workflow builder UI + reporting · P2-T4 managed-ops substrate · P2-T5 packaged vertical offering.

*
