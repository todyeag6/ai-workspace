# Client Administrator — Administration Runbook (BR-9.1 / BR-9.2)

This runbook tells the **client administrator** what they own when running the
Aiwebscapes Defensive AI Security Agent on the Local/Hybrid Toolkit. It is the
operational expression of the BR-9.1 ownership record and the BR-9.2 client-side
duties. State that can change (commit counts, hashes, push status) is NOT written
here — derive it with `bash scripts/status.sh`.

## BR-9.1 ownership record (must be populated per engagement)

The following fields are recorded at deploy time and surfaced by the platform
health endpoint. The client admin is accountable for each:

- **data location** — where relational and vector data physically reside. In a
  `local` deployment this is the in-stack `db` (MySQL) and in-stack `openviking`
  (knowledge store), never a managed-cloud DSN.
- **model location** — where the inference model runs. `local` binds the
  in-stack `ollama` service on `app_net`; `hybrid` prefers `ollama` and may burst
  to the cloud adapter for non-restricted data only.
- **Administrator** — the named client admin accountable for the instance.
- **Support boundary** — the BR-9.1 statement of what the managed service owns
  versus what the client owns. Read it from the health endpoint
  (`supportBoundary`).
- **Backup** — the client owns backup of the `db` volume and the `ollama_data`
  volume. Verify the backup owner is a named, responsible party.
- **Update** — the client owns patching of the host, the Docker engine, and the
  image versions pinned in `compose.yaml`. Verify the update owner is named.
- **Exit** — the portability / exit plan: how data and models are exported and
  the instance decommissioned without lock-in.

## BR-9.2 client-side duties (the client owns these)

- **physical security** — the host hardware and facility are the client's
  responsibility; the platform assumes a trusted physical boundary.
- **Endpoint** — client workstations accessing the dashboard are client-managed.
- **network** — the LAN/WAN that carries traffic to the instance is client-owned;
  `app_net` and `scanner_net` segmentation is enforced in `compose.yaml`.
- **identity** — the client provisions and governs administrator accounts.
- **Patching** — the client applies OS, engine, and image updates on the schedule
  they own.

## Status, honestly

Do not trust written-down counts. Run the derived status script:

```
bash scripts/status.sh
```

It reports the current branch, commit, and working-tree state from git at run
time. A runbook that quotes a number here is stale by the next commit.

## Support boundary in practice

If something is outside the BR-9.1 support boundary (e.g. host OS failure), the
client admin owns the response; the managed-service support tier does not. Escalate
per the engagement's SupportModel contacts.
