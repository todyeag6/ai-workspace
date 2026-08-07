# Aiwebscapes Platform — Comprehensive Session Handoff (Phase 1, through T11)

**Prepared:** 2026-08-07 (end of T11 execution + checkpoint)
**Repo:** `C:\Users\CTYea\dev\aiwebscapes-platform` (branch `main`, all of T1–T11 **pushed** to `origin` as of 2026-08-07; working tree clean)
**Authoritative plan:** `C:\Users\CTYea\.hermes\plans\2026-08-05_100000-aiwebscapes-production-system-plan.md` (1,180 lines — source of truth for requirement IDs)
**Baseline docs (authoritative, `.docx`):** `C:\Users\CTYea\awsx_docs\` (PDFs are duplicates — never read them; never read `_awsx_extract/*.txt`, they are derived)
**Read order for a new session:** this file → `docs/HANDOFF.md` → the plan. This file captures live state the plan cannot.

---

# ▶ NEXT SESSION PROMPT (copy this whole block into the new chat)

You are continuing the **Aiwebscapes Platform** build — a local-first, privacy-focused AI consulting/implementation platform (PHP 8.3 + MySQL 8 + Redis, Docker Compose, PHPUnit/PHPStan/phpcs TDD gate). The previous session finished **Phase 0 and Phase-1 tasks T1–T11**; the next work is **P1-T12** (and T13–T15) toward the Phase-1 exit gate.

## Hard rules (owner directives — non-negotiable)
- **SECURITY-FIRST, always.** Security is the PRIMARY review axis for every task, not a checklist. Load-bearing guarantees you must preserve and prove: **AC-001** (tenant isolation — no unscoped client query), **AC-002** (allowlists not denylists), **AC-003** (model output that fails schema/policy produces NO external side effect), **FR-AI-006** (AI cannot autonomously authorize high-impact actions), **SEC-005** (deny-by-default), **SEC-010/SFR-AI-002** (prompt-injection defense; untrusted content is DATA, never instructions), and the **SSRF egress guard** (P1-T8). When a plan/code skeleton conflicts with a security guarantee already built, reconcile TOWARD the guarantee and flag the deviation.
- **NEVER `git push` / `force-push` without explicit per-occasion instruction.** The remote exists (`origin = https://github.com/todyeag6/ai-workspace.git`); the owner pushes their own code. As of handoff, T1–T11 are on `origin/main`; nothing is pending push.
- **Subagent summaries are ADVISORY.** Async subagents (delegate_task) routinely die on HTTP 429/524 before committing, or re-report stale state from concurrent siblings. ALWAYS re-verify with real `git` + isolated-DB gate before marking a task done; finish/commit yourself when a subagent leaves work uncommitted.
- **Verify against the `.docx` baseline, not derived text.** FR-/AC-/SEC-/LFR- IDs live in `C:\Users\CTYea\awsx_docs\` `.docx` (02 Platform FRD is the functional authority; 05 Lead FRD, 07 Defensive AI FRD add task-specific IDs).
- **Use official docs / live probes, not recalled patterns.** Owner requires best-practice-from-current-docs; probe installed binaries and official sources before asserting toolchain facts.

## Environment ground truth (do NOT re-derive)
- **Host:** Windows 10. Your `terminal` = bash (git-bash/MSYS), NOT PowerShell. POSIX paths (`/c/Users/...`). Repo MUST stay on `C:` (`E:` is removable exFAT, mounts silently empty).
- **No PHP/Composer/mysql on the host.** EVERYTHING via `docker compose exec -T app ...` (always `-T`).
- **Stack:** `app` (php:8.3-cli, `sleep infinity`, bind mount `.:/app`), `db` (mysql:8.4.11, `3307:3306`), `redis` (7). Project name `aiwebscapes-platform`.
  - DSNs: `DB_DSN=mysql:host=db;dbname=aiwebscapes`, `TEST_DB_DSN=mysql:host=db;dbname=aiwebscapes_test`, `REDIS_DSN=tcp://redis:6379`.
  - `AI_LOCAL_BASE_URL=http://host.docker.internal:11434/v1` (Ollama on Windows host, GTX 1660 Ti 6GB — **never `gemma4:12b`** on auto; `gemma4:12b` is ON-DEMAND ONLY).
  - **Ollama model policy (owner-authorized):** SINGLE-RESIDENT `hermes3:8b` is the only always-on model (MAX_LOADED_MODELS=1). `qwen3:4b` = light/bulk fallback. `qwen3.5-9b:8k` = quality alt. `nomic-embed-text` = embeddings. `OLLAMA_CONTEXT_LENGTH=8192` is INTENTIONAL — enforce the ceiling fail-safe (`ContextLimitExceeded`), do not raise it.
- **MySQL DATA lives in a Docker VOLUME** that survives container restart — stray `aiwebscapes_*_iso`/`*_verify` test DBs are NOT auto-removed by a restart; they persist until explicitly `DROP`ped (each DROP is a consent-gated SQL action — ask before dropping the batch). `restart: unless-stopped` (commit `6301283`) only revives the *process*, not the data.
- **gitleaks** from HOST (not container): `docker run --rm -v "$(pwd -W)":/repo ghcr.io/gitleaks/gitleaks:latest dir /repo --redact --no-banner --config=/repo/.gitleaks.toml` (exit 1 = leaks). Validate the scanner with a REAL planted key, never the allowlisted AWS doc key.
- **phpcs major bump to 4.0.4** (CVE-2026-67434, dev-only). Ruleset compatible; re-run `composer audit` in CI.

## First actions in a new session
```bash
cd /c/Users/CTYea/dev/aiwebscapes-platform
docker compose up -d            # bring stack (applies restart policy); wait ~30s for db healthy
# verify gate on the SHARED db first (fast sanity), THEN on an isolated DB for task work:
docker compose exec -T app vendor/bin/phpunit                                   # expect OK (161 tests, 391 assertions)
docker compose exec -T app vendor/bin/phpstan analyse --no-progress --memory-limit=512M   # [OK] No errors
docker compose exec -T app vendor/bin/phpcs --standard=phpcs.xml src tests      # 0 errors
bash scripts/ci-local.sh         # all 6 gates (run from any CWD)
```

## Verification discipline (MANDATORY per task)
1. **Isolated DB for task verification:** create `aiwebscapes_p1tNN_iso` via
   `docker compose exec -T app php -r '$p=new PDO("mysql:host=db;port=3306;charset=utf8mb4","root","root");$p->exec("CREATE DATABASE IF NOT EXISTS aiwebscapes_p1tNN_iso CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");'`
   then run gates with `TEST_DB_DSN=mysql:host=db;dbname=aiwebscapes_p1tNN_iso;charset=utf8mb4 docker compose exec -T -e TEST_DB_DSN app vendor/bin/phpunit`.
   Reason: `BackupRestoreTest` DROPs+recreates the shared `aiwebscapes_test` mid-suite (AC-004), so never run the full suite against the shared DB while another run is active.
2. **Subagent dispatch lesson (CRITICAL):** when delegating, INLINE the exact spec + name only 3–4 small files to read. NEVER pass the plan-file path as a "read this" instruction — a prior subagent (deleg_d4308e4e) burnt its whole budget researching the plan and committed nothing. The re-dispatch (deleg_3dc3dd20) that omitted the path succeeded.
3. **TDD iron law:** failing test first, then implement. phpunit.xml has `failOnWarning/Risky/Deprecation/Notice=true`.
4. **No scope creep:** modify only the files the task specifies; do NOT touch AIGateway/ToolGateway/Orchestrator/RateLimiter/ci.yml/TestCase.php/BackupRestoreTest/NoUnscopedClientQueryRule/composer.json unless the task says so.
5. One class per file (PSR-1; two classes/file breaks PSR-4 autoload). Migrations idempotent (CREATE TABLE IF NOT EXISTS, inline indexes, guarded INSERTs). Commit message EXACTLY as the plan specifies per task.

## What is DONE (Phase 1, T1–T11 — all pushed, all verified on isolated DBs)
| Task | Requirement IDs | Commit | Security highlight |
|---|---|---|---|
| P1-T1 | FR-TEN-001, FR-IDENT-* | `cf00ca8` | tenant+identity schema; `(tenant_id,email)` unique |
| P1-T2 | FR-IDENT-002 | — | `PasswordHasher` argon2id, rehash-on-upgrade |
| P1-T3 | FR-TEN-002, AC-001 | `3a69497`+ | `TenantScope` — unscoped queries structurally impossible; PHPStan `NoUnscopedClientQueryRule` forbids raw `->query()/exec()` outside `TenantRepository` |
| P1-T4 | FR-IDENT-001/003/004, SEC-005, AC-001 | `88d4095` | authz deny-by-default; 403 for wrong-tenant AND not-found (no enumeration) |
| P1-T5 | FR-AGENT-001/002/003 | `90ccdb3` | agent registry disabled-by-default, versioned |
| P1-T6 | FR-AI-002/003, AC-003 | `297e915` | `AIGateway`: invalid output → `disposition='review'`, never a side effect |
| P1-T7 | FR-AI-001/004/005/006 | `db2be7e` | Local/cloud adapters, local-first router, `InjectionFilter`; never `gemma4:12b` auto |
| P1-T7.5 | FR-AI-001/004 | `1c25f00` | `LocalModelResolver`; `hermes3:8b` single-resident; 8192 ceiling fail-safe |
| P1-T8 | FR-TOOL-001/002/003, AC-002 | `a9a4b3b` | `ToolGateway`: allowlist-only + DNS-free SSRF guard (blocks 169.254.169.254/RFC1918/loopback) |
| P1-T9 | FR-ORCH-001/002/003 | `1aa7db3` | `Orchestrator`: Redis `SET NX` idempotency (effect-free replay); high-risk waits for human approval (FR-AI-006) |
| P1-T10 | LFR-CAP-001..004, LBR-5.1 | `5dc7b63` | Public capture: honeypot accepts-not-persists; throttle **fail-closed** (429); persist-before-AI; AI failure → lead `Review`; all leads tables tenant-scoped |
| P1-T11 | LFR-DUP-001, LFR-AI-001/002/003, LFR-ROUTE-001 | `be3855e` | Duplicate **linked not overwritten** + re-analysis appends new version; **LFR-AI-002 allow-list redaction** (no PII/SSN reaches model); **deterministic rule overrides AI** (LFR-ROUTE-001); low confidence → `Review` |

**Gate status:** phpunit `OK (161 tests, 391 assertions)` · phpstan L8 `[OK] No errors` · phpcs 0.

## Next tasks (verbatim from plan)
- **P1-T12** Messaging, tasks, corrections, privacy (LFR-MSG-001/002, LFR-TASK-001, LFR-DASH-004, LFR-PRIV-001, LFR-SEC-001). Modify `src/Leads/LeadService.php`; create `src/Leads/MessageService.php`; tests `tests/Leads/MessagingTest.php`, `tests/Leads/PrivacyTest.php`. Key guarantees: idempotent send (no duplicate on retry), opt-out honored, AI correction preserves original record (append-only trail), export-then-delete retains audit only, cross-tenant delete denied (403). Commit: `feat(leads): LFR-MSG-001/002, LFR-TASK-001, LFR-DASH-004, LFR-PRIV-001, LFR-SEC-001`
- **P1-T13** Audit/notifications/observability/retention (FR-AUD-001/002, FR-NOTIF-001, FR-OBS-001, FR-DATA-002). `migrations/006_audit.sql` + `src/Audit/AuditLogger.php` etc. **Append-only via MySQL `BEFORE UPDATE`/`BEFORE DELETE` triggers that `SIGNAL SQLSTATE '45000'`** (app-level discipline alone is insufficient). Commit: `feat(platform): FR-AUD-001/002, FR-NOTIF-001, FR-OBS-001, FR-DATA-002`
- **P1-T14** Assessment + BAAF scoring (FR-ASMT-001/002, BAAF-001..006). `migrations/007_assessment.sql` + `src/Assessment/AssessmentService.php`. BAAF Table-2 weights: Business Value 25%, Feasibility 20%, Risk 20%, Adoption 15%, Maintainability 10%, Time-to-Value 10% ("higher raw risk reduces total score"). Prohibited-risk + ownerless-process exceptions block decisions. Commit: `feat(assessment): FR-ASMT-001/002 + BAAF scoring and decision rules`
- **P1-T15** Dashboard + WCAG 2.2 AA (FR-DASH-001/002, LFR-DASH-001/002/003, A11Y-001..006). `src/Dashboard/DashboardController.php` + twig + `public/index.php`. **Manual a11y pass is MANDATORY** (axe-core alone insufficient). Commit: per plan.

## Open questions the plan says MUST resolve before/at Phase-1 exit gate (do NOT silently assume)
1. SLA numbers + performance budgets (NFR Table 5 "agreed per client") — for objective release-gate item 7.
2. Pen-test window, authorizing party, environment (SEC-009, SFR-AUTH-001) — **book before Phase-1 exit**; it's a gate, not a surprise.
3. Standards register cadence — confirm owner + next review date. (The Standards_Research_Register.txt already correctly lists BOTH "OWASP ASVS 5.0.x" AND "OWASP AISVS" — an earlier handoff note suggesting an "AISVS→ASVS" fix was WRONG; no change needed.)
4. First tenant's data classes — drives LFR-AI-002 redaction config.
5. **SEC-008 branch protection is BLOCKED by the plan tier** (GitHub Free private repo: both legacy branch-protection and rulesets APIs return `403 "Upgrade to GitHub Pro or make this repository public"`). Decision: stay private + free; owner pushes own. Document SEC-008 as OPEN, not skipped.

## Reusable skills (load with skill_view)
- `php-docker-tested-build` — full Windows-MSYS PHP/Docker TDD runbook (CRLF, `mysql-client`, gitleaks allowlist, migration idempotency, DDL-leak guard, async-subagent resilience).
- `subagent-driven-development` — patched with "Resilience: Timeouts & Stale Async Summaries" (re-verify with real git/phpunit; subagents die before committing).
- `database-test-isolation` — DDL-leak loud guard + migration idempotency contract.
- `test-driven-development`, `aiwebscapes-platform-build` — relevant for task execution.

## Gotchas log (avoid re-learning)
1. **CRLF:** `.gitattributes` forces LF; without it committed `.sh` check out CRLF in-container → `\r: command not found`. Don't remove `.gitattributes`.
2. **`mysql-client`** in Dockerfile (not `default-mysql-client`); binary is `mysql`.
3. **Two classes per file** fails PSR-1 AND breaks PSR-4 autoload.
4. **`require` is a valid PHP 8 method name** (`Secrets::require()`).
5. **gitleaks vendor phar false positives** — `.gitleaks.toml` allowlist in place; real source still scanned.
6. **Async subagents** time out (HTTP 429/524) before committing or report stale state — re-verify, then commit yourself.
7. **Daily container exit** fixed by `restart: unless-stopped`; if phpunit REDs with `getaddrinfo failed`, stack is down, not code.
8. **iso/verify DBs do NOT self-clean on restart** (Docker volume). Drop them explicitly with consent.

## Phase-1 Exit Gate (plan §995) — what remains
Suite green in BOTH cloud and local-Ollama configs (AC-006); AC-001/002/003 proven by negative tests; lead MVP 12-step E2E; 10 Lead FRD Table-4 cases pass; axe-core + manual a11y; CI green + SBOM + no critical findings; threat model updated for AI gateway + tool egress; traceability matrix complete. **T12–T15 remain before this gate.**

---

# ▶ END OF NEXT-SESSION PROMPT
*(The block above is the copy-paste prompt. The rest of this file is supporting detail for the current session and the standing record.)*

---

## Appendix A — Standards-baseline coverage (approved v1.0 register)
Reconciliation note (owner): external-facing claims must be reconciled to this baseline, not over-claimed. Each control below is enforced in code and proven by negative tests on an isolated DB.

| Baseline control | Where enforced (verified) |
|---|---|
| **OWASP ASVS 5.0.x** (V4/V5/V11) | `PasswordHasher` argon2id (T2); `AuthService` deny-by-default 403 (T4); `ActionAuthority.authorizeTransaction()` refuses high/critical (T7/T9) |
| **OWASP AISVS** (AI security) | `InjectionFilter` structural quarantine (T7); `ModelRouter` local-first (T7); `LocalModelResolver` allowlist + 8192 ceiling (T7.5) |
| **OWASP Top 10:2025 / API Top 10:2023** | `ToolGateway` DNS-free SSRF block (T8); `ToolGateway` allowlist-only AC-002 (T8); `TenantScope` AC-001 (T3) |
| **OWASP GenAI/LLM Top 10** | `InjectionFilter` SEC-010/SFR-AI-002 (T7); `ActionAuthority` no autonomous high-impact FR-AI-006 (T7/T9); `LeadService` fail-closed throttle+honeypot+persist-before-AI LBR-5.1 (T10) |
| **NIST AI RMF 1.0 + GenAI Profile** | `AIGateway` invalid→`'review'`, never side effect AC-003 (T6); `Orchestrator` effect-free replay + compensation (T9) |
| **NIST SSDF 1.1 / CSF 2.0** | `ci-local.sh` 6/6; gitleaks + SBOM; idempotent migrations; PHPStan L8 `NoUnscopedClientQueryRule` |
| **WCAG 2.2 AA** | P1-T15 (pending) — dashboard + manual a11y pass |

## Appendix B — Repo state at handoff
- `origin/main` HEAD = `e2be79e` (docs: mark P1-T11 done). Local == origin, tree clean.
- Docker `db` currently holds only `aiwebscapes_test` (all stray iso/verify DBs dropped 2026-08-07).
- `vendor/` and `.phpunit.cache/` are expected untracked (gitignored).

*This is a living snapshot. The authoritative plan is the `.hermes/plans/...` file; this doc captures live repo state the plan cannot.*
