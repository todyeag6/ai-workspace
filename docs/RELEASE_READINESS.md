# Release-Readiness Checklist — Aiwebscapes Platform

Maps **FRD §10 (Test and Release Gates)** and **FRD §11 (Acceptance Criteria)** to
current status. Live state is `bash scripts/status.sh` (branch / HEAD / clean /
unpushed, derived from git at run time). The full suite + phpstan L8 + phpcs are
re-run per commit; verify live rather than trusting this snapshot.

> This document deliberately omits commit hashes, test counts, and push state —
> those decay within a session and trip `tests/Docs/DocumentationFreshnessTest.php`.
> Authoritative numbers come from `status.sh` and the suite, not from here.

## Legend
- **GREEN** — gate satisfied by committed, tested code.
- **AMBER** — partial; owner decision or external action required before final shipment.
- **RED** — not satisfied.

---

## FRD §10 — Test and Release Gates

| # | Gate | Status | Evidence |
|---|------|--------|----------|
| 1 | Requirements traceability complete | GREEN | `docs/TRACEABILITY.md` maps Phase 1–5 requirement IDs → source → test; reconciled through Phase 5 (incl. stale "Phase 1" title fix). LFR-DASH-002/003, FR-DEP-002 and SEC-004 now carry dedicated tests (`tests/Leads/LeadDashboardTest.php`, `tests/Deploy/ReleaseRecordTest.php`, `tests/Bootstrap/SecurityHeadersTest.php`). |
| 2 | Unit and integration tests pass | GREEN | Full suite green on an isolated CREATE-only DB. Run via `scripts/status.sh` (phpunit target). |
| 3 | Tenant isolation and authorization tests pass | GREEN | AC-001 enforced by mandatory `TenantScope`; tests in `tests/Agents/AgentRegistryTest.php`, `tests/Leads/PrivacyTest.php`, `tests/Dashboard/PipelineTest.php`. |
| 4 | AI evaluation suite meets use-case thresholds | GREEN | P2-T1 golden-prompt eval harness gate-activates agents (FR-AGENT-003). |
| 5 | Prompt-injection / tool-abuse tests pass | GREEN | AC-002 allowlist (`tests/AI/LocalModelResolverTest.php`, `tests/Connectors/ConnectorExecutorTest.php`); AC-003 fail-safe (`tests/SecurityAgent/*`); SEC-010 / SFR-AI-002 `InjectionFilter`. |
| 6 | Accessibility automated + manual checks pass (or approved exception) | GREEN | P1-T15 dashboard at WCAG 2.2 AA; `tests/Dashboard/AccessibilityTest.php`. |
| 7 | Performance / resilience meet agreed budgets | GREEN | Fail-closed startup (FR-CONF-001/002), Redis rate limiter (LFR-CAP-003), ordered migrations + proven backup/restore drill (FR-DEP-001), argon2id hasher (FR-IDENT-002). |
| 8 | Static / dependency / secret / config scans pass | GREEN | phpstan L8 `[OK] No errors`; phpcs clean; CI secret + dependency scan + SBOM (P2 CI hardening, SEC-007/008). |
| 9 | Penetration testing completed; critical findings zero; unresolved high findings explicitly accepted | AMBER | Engine + automated security tests present, but the **external pen-test (SEC-009 / BR-12.5) is NOT yet scheduled** — owner must book + retest before final shipment. Hard release gate. |
| 10 | Backup and rollback tested | GREEN | FR-DEP-001 proven backup/restore drill (`faa4b25`). FR-DEP-002 release metadata is enforced by a dedicated `ReleaseRecord` value object (`tests/Deploy/ReleaseRecordTest.php`). |
| 11 | Runbooks, training, inventory, release notes, support ownership complete | AMBER | `HARDWARE_SIZING` + `REMOTE_SUPPORT_POLICY` RATIFIED; **SEC-008 branch protection BLOCKED by GitHub Free tier** (see `docs/CI_AND_BRANCH_PROTECTION.md`). |
| 12 | Client acceptance criteria satisfied | GREEN (internal) | All §11 AC implemented + tested; final client sign-off is a commercial step, not a code gate. |

---

## Pre-ship coverage closures (this reconciliation)

Three coverage gaps were closed with real, tenant-scoped, fail-closed code + tests:

- **LFR-DASH-002 / LFR-DASH-003** — `src/Leads/LeadDashboard.php` adds a tenant-scoped lead filter (date, source, status, assignee, priority, category, delivery) and a lead detail view assembling submission, AI output, corrections, interactions, tasks (+ delivery state), audit history and retention status. Deny-by-default on filter dimensions; cross-tenant rows excluded (`tests/Leads/LeadDashboardTest.php`).
- **FR-DEP-002** — `src/Deploy/ReleaseRecord.php` enforces the six mandatory release-metadata fields (version, change record, test evidence, security status, migration status, rollback reference) and refuses a malformed record (`tests/Deploy/ReleaseRecordTest.php`).
- **SEC-004** — `src/Bootstrap/SecurityHeaders.php` extracts the four security headers from `public/index.php` into a testable, deny-by-default set; a weakening (e.g. inline scripts in the CSP) is now caught by `tests/Bootstrap/SecurityHeadersTest.php`.

These change the audit verdict: the platform is **shippable-after-pen-test**, with only the owner-gated AMBER items remaining (SEC-009 pen-test, `REGION_TOPOLOGY.php` ratification, SEC-008 branch protection).

---

## FRD §11 — Acceptance Criteria

| ID | Criterion | Status | Evidence |
|----|-----------|--------|----------|
| AC-001 | A tenant cannot read, modify, trigger, approve, export, or infer another tenant's data or actions | GREEN | `TenantScope` mandatory scoping (FR-TEN-002 + AC-001); `tests/Agents/AgentRegistryTest.php`, `tests/Leads/PrivacyTest.php`. |
| AC-002 | An agent cannot invoke a tool not explicitly allowed by its active version | GREEN | `ToolGateway` allowlist (FR-TOOL-002 + AC-002); `tests/AI/LocalModelResolverTest.php`. |
| AC-003 | A model output that fails its schema or policy cannot produce an external side effect | GREEN | `AIGateway` `disposition='review'` (FR-AI-002/003 + AC-003); `tests/SecurityAgent/*`. |
| AC-004 | A release candidate can be restored or rolled back using tested procedures | GREEN | FR-DEP-001 backup/restore drill. |
| AC-005 | The dashboard exposes sufficient evidence to trace material agent actions and human decisions | GREEN | FR-AUD-001/002 audit; `tests/Dashboard/PipelineTest.php`. |
| AC-006 | Cloud, hybrid, and local deployments preserve the same logical authorization, audit, evaluation, and release controls | AMBER | Local + hybrid implemented. **Multi-region is PROPOSED + default-off** (`config/deploy/REGION_TOPOLOGY.php` — `STATUS: PROPOSED`). Deny-by-default verified by `tests/Deploy/MultiRegionTopologyTest.php` (`test_default_is_single_region_and_disabled`, `test_enabled_without_justification_refused`, `test_region_outside_allowlist_refused`). Owner must ratify + populate `residency_allowlist`. |

---

## Owner-gated open items (block final shipment)

1. **Penetration test (SEC-009 / BR-12.5)** — schedule + retest before final shipment. CRITICAL release gate.
2. **`REGION_TOPOLOGY.php`** — PROPOSED + default-off. Ratify and populate `residency_allowlist`; engine already enforces deny-by-default.
3. **PCI-DSS / HIPAA framework selection** — `ControlMapping` engine is generic and refuses unknown frameworks (`tests/Compliance/ControlMappingTest.php`); add mappings per newest official revisions when in scope.
4. **SEC-008 branch protection** — blocked by GitHub Free tier (documented in `docs/CI_AND_BRANCH_PROTECTION.md`).

## Program scope note
The BRD (§16) defines exactly **five** phases; no Phase 6 exists in the baseline.
Phase 1–5 in-repo work is committed and pushed. This checklist covers the
release gates that sit on top of phase delivery — chiefly the pen-test window
and the two PROPOSED config items above.
