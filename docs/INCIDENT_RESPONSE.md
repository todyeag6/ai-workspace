# Incident Response Runbook (BR-12.6)

> **BR-12.6 (verbatim, from the AI WebScapes company BRD):**
> "Every solution shall include secure configuration, backup/restore procedures, logging, incident contacts, vulnerability intake, patching responsibility, and end-of-service handling."

This runbook is the operational artifact that satisfies BR-12.6 for the
`aiwebscapes-platform` repository. It is not generic guidance — every command
and file path below points at a real artifact in this repo. Where a control is
deferred (GitHub remote, Dependabot, CodeQL) that is called out explicitly as an
**OPEN ITEM** rather than silently skipped.

---

## 1. Purpose & scope

**Compliance statement.** This document is the BR-12.6 deliverable. It covers:

- secure configuration — see `src/Config/Secrets.php` (fail-closed secret loading) and `.env.example`;
- backup/restore procedures — `scripts/backup.php`, `scripts/restore.php`, `scripts/migrate.php`, proven by `tests/Infra/BackupRestoreTest.php` (AC-004);
- logging — `docker compose logs` capture (§6) and application `error_log()` calls (e.g. `legacy/api/demo-request.php`);
- incident contacts — §2;
- vulnerability intake — §9 (maps to SEC-007 / SEC-008);
- patching responsibility — §9 (accountable role named);
- end-of-service handling — §10.

**Scope.** The `aiwebscapes-platform` stack: `app` (php:8.3), `db` (MySQL 8),
`redis` 7, orchestrated by `compose.yaml`. The firm operates a **managed-services
client base**, so most incidents have a client-impact dimension addressed in §7.

**Related security requirements (quoted where they map):**

- **SEC-003** (FRD line 70): *"Perform threat modeling for each material agent,
  connector, deployment model, and data-flow change."* The threats this runbook
  responds to are enumerated in `docs/THREAT_MODEL.md`; review that model on every PIR (§8).
- **SEC-007** (FRD line 74): *"Maintain dependency inventory/SBOM, version pinning,
  automated vulnerability scans, patch policy, and provenance checks."* → §9.
- **SEC-008** (FRD line 75): *"Use branch protection, code review, static analysis,
  secret scanning, dependency scanning, and repeatable builds."* → §9 (patching/change).
- **AC-004** (FRD line 105): *"A release candidate can be restored or rolled back using
  tested procedures."* → §5 step 6 (restore/rollback).

---

## 2. Roles & contacts

Fill the placeholders with real values before this runbook is relied upon. Do
**not** put secrets in this file — only names, emails, and phone numbers. The
`[NAME]` / `[EMAIL]` / `[PHONE]` tokens are templates, never live credentials.

| Role | Responsibility during an incident | Name | Email | Phone |
|------|-----------------------------------|------|-------|-------|
| **Security Lead** | Declares SEV level, owns containment decision, final authority on evidence handling | `[NAME]` | `[EMAIL]` | `[PHONE]` |
| **Engineering On-Call** | Executes containment/recovery commands, runs the backup/restore drill | `[NAME]` | `[EMAIL]` | `[PHONE]` |
| **Comms / Liaison** | Internal status updates, client notification (§7), regulatory coordination | `[NAME]` | `[EMAIL]` | `[PHONE]` |
| **Legal / Privacy** | Breach-assessment, regulatory duty call (§7), privilege | `[NAME]` | `[EMAIL]` | `[PHONE]` |
| **Client Success** | Per-client impact communication for managed-services accounts | `[NAME]` | `[EMAIL]` | `[PHONE]` |

Out-of-hours escalation: `[ESCALATION_PROCEDURE]`. Page the Security Lead first;
the Security Lead pulls in Engineering On-Call and Comms.

---

## 3. Severity ladder

| Severity | Definition / concrete triggers | First-response SLO | Status-update cadence |
|----------|--------------------------------|--------------------|-----------------------|
| **SEV1** | Confirmed tenant PII exfiltration; active ransomware / encryption; complete platform outage > 30 min; auth bypass affecting multiple clients | Acknowledge ≤ 15 min; Security Lead engaged ≤ 30 min | Every 30 min until contained |
| **SEV2** | Single-client data exposure; authentication/authorization bypass (one client); successful secret leak requiring rotation | Acknowledge ≤ 30 min | Every 1 h |
| **SEV3** | Limited DoS (rate limiter holding but degraded); a failed control with **no** confirmed impact; a failing CI gate that blocks releases | Acknowledge ≤ 2 h (business hours) | Daily |
| **SEV4** | Low-impact issue handled in the normal flow (a logged warning, a deferred vuln with a documented mitigation) | Next business day | At PIR only |

Escalation: any SEV3 that shows confirmed client impact is immediately re-rated
to SEV2. Any SEV2 with evidence of cross-client reach is re-rated to SEV1.

---

## 4. Detection sources

Incidents surface from these real channels in this repo:

1. **CI secret / dependency gates failing** — `scripts/ci-local.sh` (gates 3, 5) and
   `.github/workflows/ci.yml`. A `composer audit` finding or a `gitleaks` hit is a
   SEV3+ input to §9.
2. **Static analysis** — `phpstan` level 8 (gate 2) and `phpcs` PSR-12 (gate 1) in
   `scripts/ci-local.sh`. A new high-severity `phpstan` error blocking merge is a SEV3.
3. **Application logging** — `error_log()` calls (e.g. `legacy/api/demo-request.php`
   lines 51, 126) surfaced via `docker compose logs app`.
4. **Monitoring** — **OPEN ITEM**: no runtime monitoring/alerting is built yet
   (forward-referenced from the threat model). Until it exists, rely on client
   reports and log review. Track stand-up of monitoring as a PIR action item.
5. **Client reports** — managed-services clients reporting anomalies via Client Success.
6. **Threat-model-identified gaps** — `docs/THREAT_MODEL.md` enumerates the attack
   surface; a realized gap there is a likely incident root cause.

---

## 5. Containment playbook (ordered)

> **Golden rule (evidence first):** take the §6 snapshot *before* any destructive
> action. `scripts/restore.php` refuses to drop a database without `--confirm`
> (and `--allow-non-test` for a non-`_test` target), but it will obey those flags
> if given. Snapshot first.

1. **Identify.** Confirm the SEV level (§3) and the affected client(s). Capture the
   initial `docker compose logs` (§6) before touching anything.
2. **Isolate.**
   - *Stop the app tier:* `docker compose stop app` (or
     `docker stop aiwebscapes-platform-app-1 aiwebscapes-platform-redis-1`).
     Do **not** stop `db` until after the backup snapshot in step 3.
   - *Block a source IP at the rate limiter / edge:* the public intake
     `legacy/api/demo-request.php` is throttled by `src/Security/RateLimiter.php`,
     a fixed-window counter keyed on the HMAC of the client IP in shared Redis
     (`security.rate_limit_max_attempts`, `security.rate_limit_window_seconds`,
     `security.ip_hash_secret` in config). To blunt a DoS, tighten those config
     values and/or null-route the offending IP at the host/edge — do not edit
     `RateLimiter.php` in an emergency (that needs the §9 change flow).
   - *Rotate a compromised secret:* see step 3 of §6 and the note below.
3. **Preserve evidence (snapshot BEFORE any destructive action).**
   - DB snapshot:
     ```bash
     php scripts/backup.php \
       --dsn='mysql:host=db;dbname=aiwebscapes;charset=utf8mb4' \
       --out=/app/backups/aiwebscapes-incident-$(date +%s).sql.gz
     ```
   - Capture `docker compose logs` and git history (§6).
4. **Eradicate.** Remove the attacker's foothold: rotate the leaked secret
   (update the environment value; `.env.example` documents the key names — real
   values come from the environment and are **never** committed), bounce the
   `app` container (`docker compose restart app`), and confirm `App\Config\Secrets`
   fails closed if the value is blank. Patch the exploited code via §9.
5. **Recover.** Restore from the proven drill if data was destroyed:
   ```bash
   php scripts/restore.php \
     --dsn='mysql:host=db;dbname=aiwebscapes;charset=utf8mb4' \
     --in=/app/backups/aiwebscapes-incident-<ts>.sql.gz \
     --drop-database --confirm --allow-non-test
   php scripts/migrate.php \
     --dsn='mysql:host=db;dbname=aiwebscapes;charset=utf8mb4'
   ```
   A bare `--dsn` restore (no `--drop-database`) will *not* destroy data; the
   destructive drop requires all three flags by design.
6. **Verify & communicate.** Re-run the AC-004 evidence logic:
   `tests/Infra/BackupRestoreTest.php` seeds rows, drops, restores, and asserts
   byte-identical counts. Mirror that locally to prove the restore before
   declaring recovery. Then notify per §7 and open the PIR (§8).

---

## 6. Evidence handling

Capture, in order, and **do not tamper with the running system before snapshotting**:

| Evidence | How to capture | Notes |
|----------|---------------|-------|
| Container logs | `docker compose logs --no-color --timestamps app > incident-<id>-app.log 2>&1` | Capture before `docker compose stop`. |
| Database snapshot | `php scripts/backup.php --dsn=... --out=...` (see §5) | gz dump; `backups/` is gitignored — never commit it. |
| Git history | `git log --oneline --stat <range>` and `git blame <file>` | Identifies when/where a bad change landed. |
| SBOM | `sbom.xml` (generated by `scripts/ci-local.sh` gate 4 / CI) | Compare component hashes against the suspected-vuln advisory. |
| Secret exposure | `docker compose logs` + the offending `.env`/env source (not committed) | Prefer `gitleaks` re-scan (`scripts/ci-local.sh` gate 5) over manual grep. |

**Chain of custody.** Write each artifact to `incident-<id>/` with a manifest
(`sha256sum * > manifest.sha256`). Record who captured it, when, and from which
host. If a secret was leaked, rotate it (update the env value; `.env.example`
documents keys) and bounce `app` — `App\Config\Secrets::validateRequired()` will
then refuse to boot if any required value is blank or missing (fail-closed).

---

## 7. Client notification

AI WebScapes runs a **managed-services client base**, so many incidents carry a
client-impact duty.

**When to notify.**
- SEV1 / SEV2 with confirmed or suspected client data exposure → notify the
  affected client(s) **and** Legal/Privacy **before** the next business day; do
  not wait for full root-cause.
- SEV3 with no confirmed impact → notify Client Success internally; client
  comms only if the PIR (§8) re-rates upward.

**How.** Comms/Liaison drafts; Legal/Privacy reviews for privilege and
regulatory posture; Client Success delivers through the existing account channel.

**Template language (fill brackets, do not over-share IOCs prematurely):**

> Subject: Security incident affecting your AI WebScapes environment
>
> We detected a security incident on [DATE/TIME] affecting [SCOPE]. We have
> contained the issue, preserved evidence, and are executing our incident
> response runbook (`docs/INCIDENT_RESPONSE.md`). At this time we have
> [confirmed / no evidence of] exposure of your data. We will share a full
> post-incident review within [TIMEFRAME]. Your point of contact is [NAME].

**Regulatory note.** Breach-notification duties are **jurisdiction-specific**.
This runbook gives no legal advice. Consult Legal/Privacy and outside counsel
for any statutory notification clock (e.g. GDPR 72h, US state schemes). Track the
deadline as a PIR action item.

---

## 8. Post-incident review (PIR)

Held within **5 business days** of SEV1/SEV2 closure (SEV3 at the Security Lead's
discretion). The PIR document records:

1. **Timeline** — detection → identify → contain → eradicate → recover → close,
   anchored to the §6 evidence timestamps.
2. **Root cause** — link to the specific threat-model entry in
   `docs/THREAT_MODEL.md` (SEC-003 cadence: the model is updated whenever a new
   class of incident appears).
3. **Action items** — each with an owner and due date. At minimum: the fix (§9),
   any monitoring gap closed (§4 item 4), and a threat-model update.
4. **Lessons** — what the runbook itself got wrong or was missing, and a patch to
   this document.

The PIR is stored alongside the incident evidence and referenced from the next
threat-model review.

---

## 9. Vulnerability intake & patch responsibility (SEC-007 / SEC-008)

**Accountable role:** **Security Lead** owns triage and owner assignment;
**Engineering On-Call** (or the assigned engineer) owns the fix; **Comms/Liaison**
owns any externally-disclosed advisory.

**Intake sources.**
- `composer audit` (CI gate 3) — dependency CVEs.
- `gitleaks` (CI gate 5, `.gitleaks.toml`) — secret exposure.
- `phpstan` / `phpcs` (gates 2/1) — code-level risk.
- Pentest, client report, or external researcher — route to Security Lead.

**Flow.**
1. **Intake** — record in the tracker with source, CVE/identifier, and severity.
2. **Triage** — Security Lead maps it to SEV (§3) and the SEC-007/008 control it
   violates, and assigns an owner.
3. **Fix in a branch** — SEC-008 requires branch protection. Until the GitHub
   remote exists this is an **OPEN ITEM** (see `.github/workflows/ci.yml` TODO):
   today, develop on a feature branch and require a peer review before merge to
   `main`; the CI workflow documents the exact branch-protection settings to
   enable once a remote exists.
4. **CI gates must pass** — the change must clear all six gates of
   `scripts/ci-local.sh` (PSR-12, phpstan L8, `composer audit`, SBOM,
   `gitleaks`, phpunit) before merge. No merge that fails a gate.
5. **Cadence** —
   - *Emergency patch*: SEV1/SEV2-exploitable or active exploit → out-of-band,
     same-day, with expedited review but **never** skipping the gates.
   - *Scheduled patch*: ≤ 30 days for high, ≤ 90 days for medium/low, tracked to
     closure.
6. **SBOM regeneration** — re-run the CycloneDX gate so `sbom.xml` reflects the
   patched dependency set.
7. **Close** — verify in `composer audit` / re-scan, update the threat model if a
   new class, and note closure in the PIR.

The GitHub **Dependabot** and **CodeQL** slots are **deferred until a remote
exists** (tracked as an OPEN ITEM in `scripts/ci-local.sh` / `ci.yml`); until
then `composer audit` + `gitleaks` + `phpstan` are the active automated scans.

---

## 10. End-of-service handling (BR-12.6)

When offboarding a client or deprecating a component:

1. **Final backup** — `php scripts/backup.php --dsn=... --out=...` of the
   client's data; hand the (decrypted, access-controlled) dump to the client or
   archive per contract.
2. **Data return / destruction** — return the dump to the client, then securely
   delete the live data (`scripts/restore.php` onto a fresh DB is *not* needed;
   a targeted `DELETE` / schema drop is). Record destruction in the manifest.
3. **Credential revocation** — remove the client's secrets from the environment;
   confirm `App\Config\Secrets` would now fail closed if the `app` tier restarted.
4. **Config archival** — snapshot the client's `.env`-derived config and the
   relevant `compose.yaml`/migration state to cold storage; reference
   `scripts/migrate.php` ledger (`schema_migrations`) for schema version at exit.
5. **Close out** — note end-of-service in the client record and feed any lessons
   into the threat model.

---

## 11. Cross-references

- `docs/THREAT_MODEL.md` — the SEC-003 threat model this runbook operationalizes.
- `docs/adr/0001-modular-monolith.md` — architecture decision record (deployment model context for containment/rollback).
- `scripts/backup.php` — gz logical backup (§5, §6, §10).
- `scripts/restore.php` — drop+recreate+load restore, guarded by `--confirm`/`--allow-non-test` (§5, §6).
- `scripts/migrate.php` — ordered migrations with `schema_migrations` ledger (§5, §10).
- `scripts/ci-local.sh` — the six CI gates; the vulnerability-intake evidence source (§4, §9).
- `tests/Infra/BackupRestoreTest.php` — AC-004 proof the backup/restore path works (§1, §5).
- `src/Config/Secrets.php` — fail-closed secret loading; rotate-on-leak anchor (§5, §6, §10).
- `src/Security/RateLimiter.php` & `legacy/api/demo-request.php` — DoS throttle / public intake (§4, §5).
- `.env.example` — secret key documentation (never holds live values) (§1, §5, §6, §10).
- `.gitleaks.toml` & `.github/workflows/ci.yml` — secret/dependency scan config (§4, §9).
- `compose.yaml` — the `app` / `db` / `redis` stack; the restart/rollback artifact (§1, §5).
