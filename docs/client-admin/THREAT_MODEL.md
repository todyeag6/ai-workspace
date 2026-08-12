# Local/Hybrid Toolkit — STRIDE Threat Model (Phase 4)

STRIDE assessment of the Aiwebscapes Local/Hybrid Toolkit deployment surface. This
is the Phase 4 extension over the base platform; it addresses the new attack
surfaces introduced by the in-stack `ollama` and `openviking` services and the
opt-in remote-support telemetry. State that changes commit-to-commit is not
recorded here — derive current truth with `bash scripts/status.sh`.

Defence-in-depth posture: `app_net` carries business systems; `scanner_net` is the
isolated scanner segment that no production service attaches to (SFR-SELF-001).
All egress is `deny-by-default`.

## Spoofing
- In-stack `ollama` / `openviking` are reachable only on `app_net`; they accept no
  external auth and are not exposed off-host. Spoofing risk is contained to the
  trusted LAN segment the client owns (BR-9.2).
- Administrator identity is the client's responsibility (BR-9.2 identity duty).

## Tampering
- `ollama` model pulls are pinned to the `ollama_data` volume; the image is pinned
  in `compose.yaml`. Tampering of the model store requires host-level access, which
  is the client's physical/endpoint responsibility.
- `openviking` knowledge store is read/write only via the host-reachable endpoint;
  no container other than `app` may reach it.

## Repudiation
- All deployment and support actions are audited via the existing audit ledger
  (ManagedOps). The opt-in telemetry sends only health/version/exception counts, so
  it cannot repudiate an operational action — it is observability, not an audit source.

## Information disclosure
- `openviking` holds the knowledge corpus; for a `local` deployment it is in-stack
  and must not be pointed at a managed-cloud DSN (FR-DATA-001). The `LocalDataServices`
  validator refuses that configuration.
- Telemetry payload is a CLOSED set (health / version / exception count) — never
  client data or leads (AC-001/002). It is disabled unless the policy is enabled AND
  the endpoint is allowlisted (SEC-005, FR-TOOL-003).
- `restricted`-class AI data never takes the cloud egress path (SFR-SELF-003); the
  hybrid profile refuses it at the deployment-profile layer.

## Denial of service
- In-stack services share host resources; the hardware-sizing profile
  (`HARDWARE_SIZING.php`) bounds the deployment to a tier the host can sustain.
- `stack-up.sh` brings services up idempotently and waits on the `db` healthcheck.

## Elevation of privilege
- The scanner runs isolated on `scanner_net`; even a bypassed guard cannot reach
  `db`/`redis` (defence in depth). `ollama`/`openviking` have no privilege beyond
  their own service account and no mount of host paths beyond their data volume.
- Remote support cannot elevate: it is observability-only and deny-by-default.

## Phase 4 residual risks (documented, not closed by code)
- Live network isolation of `ollama`/`openviking` is proven by the compose
  declaration + a single-container harness test, not a full multi-host pen test
  (book per SEC-009 before release).
- Telemetry endpoint allowlist must be ratified by the owner before enablement.
