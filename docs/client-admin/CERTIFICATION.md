# Client Administrator — Certification Checklist (BR-9.1)

Complete this certification checklist at handover to certify the Local/Hybrid Toolkit deployment
satisfies the BR-9.1 ownership record. Each item must be signed by the client
administrator. Do not certify on written-down counts — verify with
`bash scripts/status.sh` and the live health endpoint.

## Ownership record (BR-9.1)

- [ ] **Data location** confirmed: relational + vector data are on-prem for a
      `local` deployment (no managed-cloud DSN).
- [ ] **Model location** confirmed: `local`/`hybrid` binds the in-stack `ollama`
      service; cloud burst limited to non-restricted data (SFR-SELF-003).
- [ ] **Administrator** named and accountable.
- [ ] **Support boundary** statement agreed and visible on the health endpoint.
- [ ] **Backup** owner named; `db` and `ollama_data` volumes are backed up.
- [ ] **Update** owner named; image/host patch schedule owned by the client.
- [ ] **Exit** plan documented: data + model export and decommission procedure.

## Client-side duties (BR-9.2)

- [ ] **Physical security**, **endpoint**, **network**, **identity**, and
      **patching** responsibilities acknowledged by the client.

## Toolkit controls

- [ ] Network segmentation verified: `ollama` and `openviking` on `app_net` only,
      never on `scanner_net` (SFR-SELF-001).
- [ ] Remote-support telemetry confirmed `deny-by-default`; enabled only with an
      allowlisted endpoint and no client-data payload (SEC-005, AC-001/002).

## Certification statement

"I certify the above BR-9.1 ownership record is populated and the client accepts
the BR-9.2 duties for this deployment."

Signed: ____________________  Date: ____________
