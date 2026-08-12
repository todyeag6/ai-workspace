# Client Administrator — Operations Runbook (Local/Hybrid Toolkit)

Day-to-day operation of the Local/Hybrid Toolkit. All services are defined in
`compose.yaml`. State that changes commit-to-commit is not recorded here — run
`bash scripts/status.sh` for current truth.

## Bringing the stack up

```
bash scripts/stack-up.sh --size medium --deploy-config deploy.config.php
```

- `--size` is `small | medium | large` (default `medium`) and selects the
  hardware-sizing profile from `config/deploy/HARDWARE_SIZING.php`.
- `stack-up.sh` waits for the `db` healthcheck before reporting ready.
- Idempotent: re-running does not recreate healthy services.

## In-stack services (local / hybrid)

- **db** (MySQL) — relational data, on `app_net` only.
- **redis** — cache/session, on `app_net` only.
- **ollama** — local inference. On `app_net` ONLY; never on `scanner_net`. Local
  and hybrid deployments bind this service; the cloud adapter is used only for
  non-restricted burst (SFR-SELF-003).
- **openviking** — vector / knowledge store. On `app_net` ONLY, reaches the host's
  OpenViking via `host.docker.internal`. Relational data stays in-stack (FR-DATA-001).
- **scanner_net** — the isolated scanner segment. No production service attaches to
  it (SFR-SELF-001). The ScannerInfrastructureGuard enforces this in-process; the
  compose declaration is the posture it checks.

## Network segmentation (do not cross)

`app_net` carries business systems; `scanner_net` is isolated. A scanner on
`scanner_net` cannot reach `db`/`redis` even if a guard were bypassed.

## Opt-in remote support (deny-by-default)

Telemetry is OFF unless `config/deploy/REMOTE_SUPPORT_POLICY.php` sets
`enabled = true` AND names an allowlisted endpoint. When enabled it sends only
health / version / exception counts — never client data or leads (SEC-005,
FR-TOOL-003, AC-001/002). To ratify, flip `status` to `RATIFIED` and fill
`allowed_endpoints`, then re-run the pinning test.

## Health & support boundary

The health endpoint reports dependency status fail-visibly and exposes the BR-9.1
support boundary (`supportBoundary`) showing the backup owner and update owner.
