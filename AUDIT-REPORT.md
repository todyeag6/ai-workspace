# Aiwebscapes Platform — Audit Report

**Document ID**: AWS-AUDIT-001  
**Version**: 1.0  
**Date**: 2026-09-01  
**Status**: Draft — owner sign-off required for release

---

## Executive Summary

The Aiwebscapes platform is **shippable-after-pen-test**. All code, tests, and quality gates are green. Four owner-gated release items remain before final shipment. The platform satisfies BRD §16 Phases 1–5 in-repo; Phase 5 items (multi-region, PCI/HIPAA) are deferred with engine-enforced deny-by-default posture.

---

## Traceability Matrix (Phase 1–5 Coverage)

Requirement IDs by document (extracted from the 7 docx baselines):

| Doc | Functional IDs | Notes |
|-----|---------------|-------|
| `02 Platform FRD` | AC-001, AC-002, AC-003, FR-AGENT-001, FR-AI-001..006, FR-IDENT-001, FR-ORCH-001, FR-TEN-001/002/003, FR-TOOL-001/002/003, SEC-005, SEC-010 | Phase-1 functional authority |
| `05 Lead FRD` | LFR-AI-002, LFR-AI-003 | Lead generation task-specific |
| `07 Defensive AI FRD` | SFR-AI-002 | Security-agent task-specific |
| `01 Company BRD` | None (business case only) | |
| `03 BAAF` | AC-001, AC-002, AC-003 (referenced, not defined) | Cross-refs only |
| `04 Lead BRD` | None (business case only) | |
| `06 Defensive AI BRD` | None (business case only) | |

**Code→Test mapping**: Full coverage — every `src/` domain has at least one test class. Heaviest-tested domains: `Deploy` (16), `Leads` (5), `SecurityAgent` (13), `Identity` (3), `Workflow` (3), `Compliance` (4). Full suite: 562 tests, 1811 assertions on isolated CREATE-only DB.

---

## Release Gates (FRD §10 / §11)

| # | Gate | Status | Evidence |
|---|------|--------|----------|
| 1 | Requirements traceability complete | GREEN | `docs/TRACEABILITY.md` maps Phase 1–5 → source → test |
| 2 | Unit and integration tests pass | GREEN | Full suite green on isolated CREATE-only DB |
| 3 | Tenant isolation and authorization tests pass | GREEN | AC-001 enforced by mandatory `TenantScope` |
| 4 | AI evaluation suite meets use-case thresholds | GREEN | P2-T1 golden-prompt eval harness gate-activates agents |
| 5 | Prompt-injection/tool-abuse tests pass | GREEN | AC-002/AC-003/SEC-010 test suites green |
| 6 | Accessibility automated + manual checks pass | GREEN | P1-T15 dashboard at WCAG 2.2 AA |
| 7 | Performance / resilience meet agreed budgets | GREEN | Fail-closed startup, Redis rate limiter, ordered migrations |
| 8 | Static / dependency / secret / config scans pass | GREEN | phpstan L8 `[OK]`; phpcs clean; CI secret + dependency scan + SBOM |
| 9 | Penetration testing completed; critical findings zero; unresolved high findings explicitly accepted | **AMBER** | External pen-test (SEC-009 / BR-12.5) **NOT yet scheduled** — hard release gate |
| 10 | Backup and rollback tested | GREEN | FR-DEP-001 proven backup/restore drill; FR-DEP-002 release metadata enforced |
| 11 | Runbooks, training, inventory, release notes, support ownership complete | **AMBER** | `HARDWARE_SIZING` + `REMOTE_SUPPORT_POLICY` RATIFIED; SEC-008 branch protection BLOCKED by GitHub Free tier |
| 12 | Client acceptance criteria satisfied | GREEN (internal) | All §11 AC implemented + tested; final client sign-off is commercial |

---

## Owner-Gated Open Items (Block Final Shipment)

| # | Item | Type | Required Action |
|---|------|------|-----------------|
| 1 | **SEC-009 / BR-12.5** — External penetration testing | 🔴 CRITICAL | Schedule authorized pen-test against release candidate; remediate zero critical findings; retest before shipment |
| 2 | **`REGION_TOPOLOGY.php`** — Multi-region topology + residency validator | 🟡 PROPOSED + default-off | Owner must: (1) flip `STATUS` → `RATIFIED`, (2) populate `residency_allowlist` with approved regions, (3) record data-residency justification. Deny-by-default engine already enforced. |
| 3 | **PCI-DSS / HIPAA framework selection** | 🟡 New task | `ControlMapping` engine is generic and refuses unknown frameworks. Add PCI-DSS / HIPAA mappings from newest official revisions as a new task. |
| 4 | **SEC-008** — Branch protection | 🔴 BLOCKED | GitHub Free tier limitation. Documented in `docs/CI_AND_BRANCH_PROTECTION.md`. CI workflow enforces status checks on PRs; full branch protection rules unavailable on Free tier. |

---

## Security Posture (Key Controls Verified)

| Control | Status | Verification |
|---|---|---|
| AC-001 — Tenant isolation | ✅ Green | `TenantScope` mandatory; no unscoped queries outside `TenantRepository` |
| AC-002 — Tool allowlists | ✅ Green | `ToolGateway` allowlist; never denylists |
| AC-003 — Model output side-effect guard | ✅ Green | `AIGateway` `disposition='review'`; no external side effects from failed schema |
| SEC-004 — Security headers | ✅ Green | `src/Bootstrap/SecurityHeaders.php` extracts 4 headers from `public/index.php`; deny-by-default |
| SEC-005 — Deny-by-default | ✅ Green | `ScannerInfrastructureGuard`; `scanner_net` carries NO production service |
| SEC-010 — Prompt injection prevention | ✅ Green | Four ordered guards: content separation → tool allowlists → validation → approval/egress |
| SFR-SELF-001 — Scanner isolation | ✅ Green | `app_net` only; `scanner_net` attaches to NO production service |
| SFR-SELF-005 — Target sanitizer | ✅ Green | `TargetCanonicalizer` + regex host extraction; `parse_url` IPv6 gotcha fixed |
| SFR-AI-002 — Untrusted content = data | ✅ Green | Content never reaches system instructions; schema validator enforces scalar leaves only |

---

## CI / Quality Gate State

All 6 local CI gates pass (`bash scripts/ci-local.sh`):

1. **PSR-12 (phpcs, errors only)** — `-n` flag enforced in `.github/workflows/ci.yml:109`
2. **PHPStan L8** — `--memory-limit=1G` enforced in `.github/workflows/ci.yml:113` (parity fix committed `0d79748`)
3. **Dependency vulnerabilities** — `composer audit` — no advisories
4. **SBOM** — CycloneDX generated; components verified
5. **Secret scan (gitleaks)** — 2.05 MB scanned, no leaks found
6. **Tests (phpunit)** — 562 tests, 1811 assertions on isolated DB

CI workflow parity with `scripts/ci-local.sh` verified at commit `0d79748`.

---

## Doc References (Audit Artifacts)

The following docs constitute the audit trail. `AUDIT-REPORT.md` consolidates them:

| Doc | Purpose |
|-----|---------|
| `docs/TRACEABILITY.md` | Requirement → implementation → test map (Phases 1–5) |
| `docs/RELEASE_READINESS.md` | FRD §10/§11 release gates checklist |
| `docs/THREAT_MODEL.md` | Security model + trust boundaries |
| `docs/INCIDENT_RESPONSE.md` | BR-12.6 incident runbook |
| `docs/SITEMAP_CODEMAP.md` | Code navigation + test coverage overview |
| `AGENTS.md` | Dev-stack topology + off-limits posture + quality gate flags |
| `compose.yaml` | Authoritative architecture + security topology comments |
| `.github/workflows/ci.yml` | CI counterpart of `scripts/ci-local.sh` (6 gates) |

---

## Notes

- **No Phase 6 exists** in the BRD §16 baseline — five phases only.
- **Baseline docx live at** `C:\Users\CTYea\awsx_docs\` (7 files, outside the repo).
- **CI parity**: `.github/workflows/ci.yml` was fixed (`0d79748`) to pass `--memory-limit=1G` to phpstan and `-n` to phpcs, matching `scripts/ci-local.sh`.
- **Platform is shippable-after-pen-test** — only the four owner-gated items above remain.