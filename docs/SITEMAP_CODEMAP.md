# Aiwebscapes Platform — Code Map (Navigation Sitemap)

A learning-oriented map of the repository. Generated 2026-08-12 from the live
tree. Counts are `.php` files (src = logic, tests = verification).

> The app has **no web kernel** — controllers are array-in/array-out and tested
> directly. The only HTTP-served page is `public/index.php` (demo dashboard).
> See `public/sitemap.xml` for the SEO sitemap and `docs/SITEMAP_ARCH.svg` for
> the service/domain diagram.

## 1. Served surface
| Path | File | Purpose |
|---|---|---|
| `/login`, `/logout` | `public/index.php` | Operator sign-in and server-side session revocation (FR-IDENT-001/003/004). Public. |
| `/console` | `public/index.php` → `App\Console\AgentConsoleController` | The tenant's registered agents. **Gated**: requires `agent.console.view`, session-resolved tenant (AC-001). |
| `/console/invoke` | `public/index.php` → `App\Console\AgentInvocationController` | Runs a registered agent. **Gated**: requires `agent.invoke` + CSRF + object check. |
| `/api/v1/public/leads` | `public/index.php` → `App\Leads\LeadController` | Public lead capture (unchanged). |
| `/dashboard` (demo) | `public/index.php` | Hardened front controller → `App\Dashboard\DashboardController`. Tenant fixed server-side (AC-001). **Unauthenticated** — see `docs/adr/0003-authenticated-operator-console.md` §3.1, which records this as an open finding rather than an oversight. |
| `/assets/*` | `public/assets/` | Static stylesheets, served same-origin so the CSP stays at `style-src 'self'`. |

Authorization for the gated routes runs through `App\Security\TenantAuthMiddleware`
**before** the controller is constructed, so an unauthorised request never reaches
code that reads tenant data.

## 2. Source domains (`src/`) — 25 domains
Format: `Domain | src files | test files`
| Domain | src | tests | What it is |
|---|---|---|---|
| Agents | 9 | 1 | Agent registry / lifecycle |
| AI | 14 | 4 | Model router, local + cloud adapters |
| Assessment | 4 | 1 | Security assessments |
| Audit | 2 | 1 | Audit logging |
| Bootstrap | 1 | 1 | App bootstrap |
| Compliance | 2 | 4 | Control-mapping engine (NIST/ISO/SOC 2) |
| Config | 2 | 1 | Secrets / config (FR-CONF-002 fails closed) |
| Connectors | 7 | 1 | External connector bindings |
| Dashboard | 3 | 2 | Dashboard controller + view (A11Y-gated) |
| Data | 9 | 1 | Tenant-scoped data access (AC-001) |
| Deploy | 9 | 16 | Client-deploy + region topology |
| Eval | 4 | 1 | Eval-gated agent activation |
| Identity | 4 | 3 | Tenant identity |
| Infra | 4 | 1 | SQL splitter, CLI options, backup/restore |
| Leads | 7 | 5 | Lead capture / messaging / priority |
| ManagedOps | 5 | 4 | Managed-ops substrate (SLAs, support) |
| Notification | 2 | 1 | Notifications |
| Observability | 1 | 1 | Metrics/tracing |
| Reporting | 2 | 1 | Report assembly |
| Security | 10 | 4 | Security policy/config |
| SecurityAgent | 55 | 13 | Defensive security agent (scanners, findings, remediation) |
| Tenancy | 2 | 2 | Tenant scoping (TenantScope) |
| Tools | 4 | 1 | Tool gateway (allowlist, SEC-002) |
| VerticalOffering | 5 | 1 | Packaged vertical offerings |
| Workflow | 5 | 3 | Workflow builder |

## 3. Test coverage map
Every `src/` domain has at least one test class — **no domain is untested**.
Heaviest-tested: `Deploy` (16), `Leads` (5), `ManagedOps` (4), `Security` (4),
`SecurityAgent` (13), `Identity` (3), `Workflow` (3), `Compliance` (4).
Full suite: run `bash scripts/status.sh` (or `bash scripts/ci-local.sh`, gate 6) for the current test/assertion count — written counts go stale, so they are not recorded here.

## 4. CLI scripts (`scripts/`)
| Script | Purpose |
|---|---|
| `ci-local.sh` | The 6-gate local CI proof (phpcs, phpstan, audit, SBOM, gitleaks, phpunit) |
| `stack-up.sh` | Bring the stack up + poll `db` healthy |
| `status.sh` | Derive live build state from git (truth over prose) |
| `migrate.php` | Apply `migrations/*.sql` in order (`--dsn` mandatory) |
| `backup.php` / `restore.php` | DB snapshots |
| `deploy-client.php` | Client-deploy helper |

## 5. Docs (`docs/`)
| Doc | Purpose |
|---|---|
| `HANDOFF.md` | Ground rules; state is derived, never retyped |
| `TRACEABILITY.md` | Requirement → implementation → test map (Phases 1–5) |
| `THREAT_MODEL.md` | Security model + trust boundaries |
| `INCIDENT_RESPONSE.md` | BR-12.6 incident runbook |
| `RELEASE_READINESS.md` | FRD §10/§11 release gates |
| `CI_AND_BRANCH_PROTECTION.md` | CI + branch protection |
| `adr/` | Architecture decision records |
| `client-admin/`, `partner-program/`, `service-management/` | Runbooks |

## 6. Database
22 migrations (`migrations/000_baseline.sql` → `021_leads_priority.sql`),
applied in filename order, idempotent. Two DBs: `aiwebscapes` (app) and
`aiwebscapes_test` (test harness, auto-created + rolled back per test).

## 7. Docker services (`compose.yaml`)
`app` (workspace/runner, `sleep infinity`) · `db` (mysql:8) · `redis` (7) ·
`openviking` (knowledge store) · `ollama` (local models). `app_net` carries
production services; `scanner_net` is deny-by-default isolated (SFR-SELF-001).
