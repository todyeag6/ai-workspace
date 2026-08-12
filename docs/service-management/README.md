# Mature Service Management (Phase 5 — BRD §16, OUT-OF-REPO)

This directory holds the **mature service-management** package for the Aiwebscapes
Local/Hybrid Toolkit. It is one of the two Phase 5 themes that live **outside this
codebase** (the other is the partner program under `docs/partner-program/`).
ITIL-style service management process ownership is a commercial/ops function.

## Reuse of Phase 4 artifacts
The operational runbooks produced in Phase 4 are the foundation this package
extends:
- `docs/client-admin/OPERATIONS.md` — day-to-day stack operation.
- `docs/client-admin/ADMINISTRATION.md` — BR-9.1 ownership + BR-9.2 duties.
- `docs/client-admin/THREAT_MODEL.md` — STRIDE threat model for the toolkit.

## Out-of-repo boundary (do not implement here)
The following are owned by the service-management function, not this repo:
- Incident/problem/change management tooling and queues.
- SLA reporting to paying clients (the platform emits health/data; the managed
  service wraps it).
- Capacity planning and billing reconciliation.

## Status
Package scaffold only. Derive current repository state with `bash scripts/status.sh`.
