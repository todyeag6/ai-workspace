# ADR-0001: Modular Monolith

- **Status:** Accepted (v0.1)
- **Date:** 2026-08-05
- **Deciders:** Aiwebscapes engineering
- **Related:** [Threat Model v0.1](../THREAT_MODEL.md), Platform FRD §4–5, Plan §Phase 0

---

## 1. Context

We are building the Aiwebscapes platform from a preserved PHP baseline
(`legacy/`) plus new, tested modules under `src/`. The question is what
structural style to adopt now, before multi-tenancy (Phase 1) and the autonomous
Security Agent (Phase 1+) arrive.

Forces in play:

- A working **baseline lead-intake path already exists** in `legacy/`
  (`api/demo-request.php`, `includes/auth.php`, `config/app.php`, `schema.sql`).
  A full rewrite is unjustified risk; the baseline carries real security controls
  (prepared statements, `hash_equals` CSRF, `password_verify`, secure headers)
  that we must **reuse, not re-implement**.
- We need **fast, cheap test isolation** — every test against real MySQL 8 with
  transaction rollback (`tests/TestCase.php`), which is simplest inside one
  deployable with one database.
- The approved baseline mandates **tenancy, RBAC, an AI gateway, and an
  autonomous agent** — all of which are easier to reason about with clear module
  boundaries than with a distributed system's network and consistency overhead,
  at this stage.
- Deployment target is a single Docker Compose stack (`app` + `db` + `redis`);
  we have no orchestration platform requiring microservice decomposition.

---

## 2. Decision

Adopt a **modular monolith**:

- **One deployable**, one `composer.json`, one MySQL database, one Redis.
- **Vertical modules under `src/<Domain>/`**, each owning its namespace and
  (where stateful) its tables: `Config`, `Security`, `Infra` already exist.
- Modules communicate through **services / repositories**, never raw
  cross-module SQL. The rule: *a module may call another module's public
  service, but must not read or write another module's tables directly.*
- **`legacy/` is an explicit, ring-fenced compatibility layer — not a module.**
  It is retained as the lead-intake path and MUST NOT be expanded with new
  features; new code lives in `src/`. It is excluded from `phpcs`/`phpstan`
  (CRLF, baseline style) but its security controls are preserved verbatim.
- **AI Gateway / Security Agent** (when built) are modules like any other,
  behind the same boundaries; the local Ollama link (`AI_LOCAL_BASE_URL` →
  `host.docker.internal:11434`) is an adapter inside the AI Gateway module.

---

## 3. Consequences

### Good

- **Simple deploy & rollback:** one image, one `compose.yaml`; restore via
  `scripts/restore.php` + `scripts/migrate.php` (proven by `BackupRestoreTest`,
  AC-004).
- **Shared transactions:** cross-module operations can use one DB transaction —
  the `tests/TestCase.php` rollback harness directly supports this.
- **One test database:** the real-MySQL suite exercises tenant parity and
  migrations without multi-service test orchestration.
- **Cheap refactor:** moving logic between modules is in-process, not a
  network boundary change.

### Bad / risks (and how we contain them)

- **Coupling risk:** the single biggest failure mode is modules reaching into
  each other's tables. *Containment:* the §2 "no cross-module SQL" rule, enforced
  by code review (SEC-008) and, where feasible, schema-level separation.
- **Scaling ceiling:** a monolith scales vertically, not by isolating hot
  modules. *Containment:* the AI Gateway's provider abstraction (FR-AI-001) keeps
  the option of extracting it later without rewriting callers.
- **Blast radius:** one bug can take down the whole deployable. *Containment:*
  the CI gate (`ci-local.sh`: phpcs, phpstan L8, gitleaks, audit, SBOM, phpunit)
  plus the threat model's per-change cadence (SEC-003).

### First real test of this decision

**Multi-tenancy (Phase 1)** is the moment the modular-monolith choice is
exercised: tenant scoping must be enforced in repositories/services, not by
schema isolation alone. The `tests/TestCase.php` real-MySQL harness and the
migration idempotency contract already exist to support that work.

---

## 4. References

- [Threat Model v0.1](../THREAT_MODEL.md) — STRIDE per component, AI-risk surface.
- Platform FRD: FR-AI-001 (AI gateway abstraction), FR-TEN-002 (tenant scoping),
  SEC-003 (threat modeling cadence), SEC-008 (code review / static analysis).
- Plan §Phase 0: tasks M1–M4, P0-T1…P0-T7.
- Repo: `src/Config/`, `src/Security/`, `src/Infra/`, `legacy/` (ring-fenced),
  `tests/TestCase.php` (transaction isolation harness).
