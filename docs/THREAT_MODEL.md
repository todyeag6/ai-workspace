# Threat Model — Aiwebscapes Platform

**Version:** v0.1 (draft) &nbsp;|&nbsp; **Date:** 2026-08-05 &nbsp;|&nbsp; **Status:** Draft for review
**Scope:** Phase 0 foundation — public intake, identity, secrets, rate limiting, migrations/backup.
AI Gateway and Security Agent are documented as *forward-looking* (not yet built).

---

## 1. Methodology

This model uses **STRIDE** (Spoofing, Tampering, Repudiation, Information Disclosure,
Denial of Service, Elevation of Privilege) per component, as required by
**SEC-003**:

> "Perform threat modeling for each material agent, connector, deployment model, and data-flow change."

It is **v0.1** and is explicitly **revisited on every material change** (see
[§6 Review cadence](#6-review-cadence)). Components that do not yet exist are
marked **[PLANNED]** and carry a forward-looking threat surface only.

---

## 2. Component inventory

| Component | Trust boundary | State today | Notes |
|---|---|---|---|
| **Public Intake** | Anonymous internet → app | **Built** | `legacy/api/demo-request.php` (POST, CSRF, honeypot, Redis rate limit) |
| **Identity & Access** | Authenticated user → app | **Built** (partial) | `legacy/includes/auth.php`, `csrf.php`, `security.php`; no MFA yet |
| **Tenant Data** | App → MySQL (`db`) | **Built** (single-tenant today) | `demo_requests`, `users` (`migrations/000_baseline.sql`); multi-tenancy is Phase 1 |
| **Secrets / Config** | Env → app bootstrap | **Built** | `src/Config/Secrets.php` (fail-closed) |
| **Rate Limiting** | Shared Redis (`redis`) | **Built** | `src/Security/RateLimiter.php` (LFR-CAP-003) |
| **Migrations / Backup** | App → MySQL + files | **Built** | `scripts/migrate.php`, `backup.php`, `restore.php`; `tests/Infra/BackupRestoreTest.php` |
| **AI Gateway** `[PLANNED]` | App → Ollama (`host.docker.internal:11434`) | Not built | `compose.yaml` `AI_LOCAL_BASE_URL`; FR-AI-001 abstraction |
| **Tool Egress** `[PLANNED]` | Security Agent → external tools | Not built | Phase 1+ autonomous agent domain |
| **Security Agent** `[PLANNED]` | Agent → tools / data | Not built | `security_assets` / `scans` / `findings` / `evidence` / `remediations` tables planned |

---

## 3. STRIDE findings — components built today

### 3.1 Public Intake (`legacy/api/demo-request.php`)

| STRIDE | Scenario | Likelihood | Impact | Mitigation (existing / planned) |
|---|---|---|---|---|
| **S** Spoofing | Attacker forges a submission | Low | Low | CSRF token (`verify_csrf`, `hash_equals` + TTL) binds request to a session; honeypot field (`website`) traps bots |
| **T** Tampering | Inject malformed fields | Low | Med | `normalize_input()` length-clamps every field; INSERT uses **prepared statements** (`db()->prepare(...)->execute([...])`) — no string interpolation |
| **R** Repudiation | Deny a submitted lead | Med | Low | `ip_hash` (HMAC of client IP via `hash_ip()`) + `user_agent` persisted on every row |
| **I** Info Disclosure | Leak internals via error | Low | Med | Honeypot silently returns success; generic 422/500 messages; `secure_headers()` sets `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` |
| **D** DoS | Flood the lead form | Med | Med | **Redis shared-storage rate limiter** (`RateLimiter`, keyed on `hash_ip()`) — survives session loss, unlike the old `$_SESSION` limiter (LFR-CAP-003) |
| **E** Elevation | Submit → gain privileges | Low | High | No privilege change on this path; input never reaches auth/exec; fail-closed secrets mean a missing `APP_KEY` halts boot rather than degrading |

### 3.2 Identity & Access (`legacy/includes/auth.php`, `csrf.php`)

| STRIDE | Scenario | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| **S** | Credential stuffing | Med | High | `password_verify()` (never compares plaintext); rate limiting at intake; password hashing on registration (baseline) |
| **T** | Tamper with session | Low | High | CSRF token is single-use-per-scope with TTL; `hash_equals()` constant-time compare |
| **R** | Deny an action | Low | Med | Audit-relevant actions persist `user_agent`/`ip_hash`; sessions server-side |
| **I** | Session token theft | Med | High | **[PLANNED]** MFA-ready controls per FRD Table 2; secure headers + `HttpOnly`/`SameSite` cookie posture to confirm in Phase 1 |
| **D** | Lock out users | Low | Med | Rate limiter at the gate; account-lockout policy **[PLANNED]** |
| **E** | Vertical privilege escalation | Low | Critical | RBAC/ABAC model **[PLANNED]** (FRD Table 2); today's baseline has a single role assumption — a tracked gap |

### 3.3 Tenant Data (`demo_requests`, `users`)

| STRIDE | Scenario | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| **S/T** | Query injection | Low | Critical | Prepared statements everywhere; no raw client SQL |
| **R** | Cross-tenant write | Med (Phase 1) | Critical | **[PLANNED]** tenant scoping via repository/service methods (FR-TEN-002); the `tests/TestCase.php` real-MySQL harness exists to test tenant parity |
| **I** | PII exposure in backups | Low | High | Backups gzipped to `/backups/` (gitignored); restore drill proven by `BackupRestoreTest` (AC-004) |
| **D** | DB exhaustion | Low | Med | Connection pooling via PDO; resource limits at MySQL |

### 3.4 Secrets / Config (`src/Config/Secrets.php`)

| STRIDE | Scenario | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| **S** | Fake a missing secret | Low | High | `Secrets::validateRequired()` throws `MissingSecretException` at boot — **fail closed** (FR-CONF-002) |
| **I** | Secret in source / VCS | Low | Critical | No literal creds in `legacy/` (placeholders removed in P0-T2); `.env` gitignored; **gitleaks** in CI (`ci-local.sh` + `.gitleaks.toml`) scans source |
| **E** | Read another service's secret | Low | High | Secrets sourced from env only; no shared file; `legacy/config/app.php` requires autoloader to validate before building config |

### 3.5 Rate Limiting (`src/Security/RateLimiter.php`)

| STRIDE | Scenario | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| **D** | Burst exhausts Redis | Low | Med | Fixed-window counter with `EXPIRE` on first hit; keyed per bucket+IP |
| **T** | Spoof IP to reset counter | Med | Med | `hash_ip()` HMACs the real client IP with `ip_hash_secret`; client cannot forge the key |
| **I** | Counter state observable | Low | Low | Key names are opaque (`ratelimit:<bucket>:<hash>`); no secret data stored |

### 3.6 Migrations / Backup (`scripts/*.php`)

| STRIDE | Scenario | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| **T** | Bad migration corrupts schema | Low | High | `migrations/*.sql` must be **idempotent** (CREATE TABLE IF NOT EXISTS, inline indexes, guarded INSERTs); re-applied every test in `TestCase` |
| **R** | Unauthorized restore | Low | Critical | `restore.php` has **no default DSN** and requires `--dsn` + `--confirm` to drop a DB (prod-safe by construction) |
| **I** | Backup file exfiltration | Low | High | `/backups/` is gitignored; dump contains no `CREATE DATABASE` (cannot smuggle a target) |
| **D** | Backup job fails silently | Low | Med | `BackupRestoreTest` proves the round-trip; `composer audit` / CI gates alert on regressions |

---

## 4. AI-specific risk surface (SEC-010 / SEC-011)

The following are **mandated** by the approved baseline and apply once the
AI Gateway and Security Agent are built. They are documented here so the v0.1
model is complete even though the code is not.

> **SEC-010:** "Prevent prompt injection and excessive agency through source trust labels, instruction hierarchy, content separation, tool allowlists, validation, approval, and egress restrictions."

> **SEC-011:** "Evaluate data leakage, cross-tenant exposure, indirect prompt injection, unsafe output handling, denial-of-wallet, model/provider failure, and supply-chain compromise."

| Risk (SEC-010/011) | Current posture | Planned control (source requirement) |
|---|---|---|
| **Prompt injection** (direct) | Not built | Source trust labels + instruction hierarchy (SEC-010) |
| **Indirect injection** (via tenant data / tool output) | Not built | Content separation; untrusted content never reaches system instructions (SEC-010, SEC-011) |
| **Data leakage / cross-tenant exposure** | Single-tenant today | Tenant-scoped repositories; output filters; the `TestCase` MySQL harness tests parity (SEC-005, SEC-011) |
| **Unsafe output handling** | Not built | Output encoding + validation before any action (SEC-004, SEC-011) |
| **Denial-of-wallet** | N/A today (local Ollama, no per-call cost) | Budget/token caps in the AI Gateway (`AI_LOCAL_BASE_URL` adapter); provider cost guardrails (SEC-011, FR-AI-001) |
| **Model / provider failure** | Local Ollocama today | Provider abstraction (`FR-AI-001`) with fallback + evaluation gates; structured-output contracts |
| **Supply-chain compromise** | **Partial** — Composer deps present | **SBOM** (`sbom.xml` via cyclonedx), `composer audit`, gitleaks, phpstan in CI (P0-T5, SEC-007); lockfile pinned (`composer.lock` committed) |

---

## 5. Open risks / out-of-scope

- **Single-role auth** today — RBAC/ABAC and MFA are Phase 1 (FRD Table 2).
- **AI Gateway / Security Agent** are unbuilt; their STRIDE pass is a **gate before first production use** (§6).
- **Cross-tenant isolation** is the first real test of the modular-monolith decision (see `docs/adr/0001-modular-monolith.md`).
- **WAF / edge controls** not in scope for Phase 0.

---

## 6. Review cadence

Per **SEC-003**, this model is re-run on **every material agent, connector,
deployment-model, or data-flow change**. Minimum cadence is **per Phase gate**.
The **AI Gateway** and **Security Agent** components require a **full STRIDE pass
before their first production use**, and any new external tool egress requires an
updated §4 entry. Findings feed the incident runbook (`docs/INCIDENT_RESPONSE.md`)
and the vulnerability-intake process (BR-12.6 / SEC-007).

---

*This document is v0.1. It is a living artifact — edit it in place as controls land,
and bump the version on each material revision.*
