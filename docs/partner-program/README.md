# Partner Program Package (Phase 5 — BRD §16, OUT-OF-REPO)

This directory holds the **partner-program package** for the Aiwebscapes
Local/Hybrid Toolkit. It is one of the two Phase 5 themes that live **outside
this codebase** (the other is mature service management under
`docs/service-management/`). Commercial, legal, and SOW work for the partner
program is owned outside the repository.

## What this package contains
- Partner onboarding and certification material.
- The certification baseline partners must complete before operating an instance.

## Reuse of Phase 4 artifacts
The partner certification baseline is the BR-9.1 ownership-record certification
already produced for the client administrator:

- `docs/client-admin/CERTIFICATION.md` — the BR-9.1 ownership checklist a partner
  must sign before operating a deployment.

A partner is, for certification purposes, held to the same BR-9.1 ownership record
(data location, model location, administrator, support boundary, backup owner,
update owner, exit) and the BR-9.2 client-side duties as a direct client.

## Out-of-repo boundary (do not implement here)
The following are NOT code in this repository and are owned by the commercial/ops
function:
- Partner contracts, revenue share, and legal agreements.
- SOW generation and acceptance authority (BR-10.1/BR-10.2).
- Partner-tier pricing and marketplace listing.

## Status
Package scaffold only. State that changes (commit counts, hashes, push status) is
NOT written here — derive it with `bash scripts/status.sh`.
