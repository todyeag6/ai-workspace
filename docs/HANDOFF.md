# Aiwebscapes Platform — State

**There is no status prose in this file, on purpose.**

Every previous version of this document tried to keep a written copy of what
was built, what was pushed, and how many tests passed. That copy went stale the
moment the next commit landed, and stale copies caused real damage:

> this file still described the repo as "Phase 0 → Phase 1" with "161 tests"
> while Phase 3 was shipping, and `SESSION_HANDOFF_P1T14.md` announced work as
> "NOT YET PUSHED" that had been on `origin/main` for days.

Sessions then opened by trusting those numbers and reporting them back as fact.

Prose cannot be kept honest by discipline. So state is **derived**:

```bash
bash scripts/status.sh
```

That prints — from git, at the moment you run it — the branch, HEAD, whether
the tree is clean, the exact count of unpushed commits, the full delivered-task
list (every `feat` commit, with its requirement IDs, because the commit
subjects already are the task table), and the verify commands.

**If a markdown file and `scripts/status.sh` disagree, the script is right.**

---

## Ground rules for a session working here

1. **Never quote a remembered count.** Tests, commits, DBs, files — re-derive
   or re-count it in the same turn you state it. A number carried over from a
   prior turn or a brief is not evidence.
2. **A prepended session brief is not ground truth.** Briefs and compaction
   summaries lag reality. Run `scripts/status.sh` first and believe it over any
   inherited claim about what is built or pushed.
3. **`git log` is the task record.** Do not maintain a parallel table of what
   is done; write the requirement IDs into the commit subject and let the log
   carry it.
4. **Verify before claiming green.** Exit code 0 from a build step is not a
   passing suite. The gate commands are printed by `scripts/status.sh`.
5. **Never push without an explicit, per-occasion instruction.** Committing per
   checkpoint is expected; pushing is a separate authorization.

---

## What does live in `docs/`

These are reference documents, not status:

| File | Contents |
|---|---|
| `THREAT_MODEL.md` | Security model and trust boundaries |
| `INCIDENT_RESPONSE.md` | BR-12.6 incident runbook |
| `TRACEABILITY.md` | Requirement → implementation map (Phases 1–5) |
| `adr/` | Architecture decision records |

`TRACEABILITY.md` was reconciled to carry Phase 1 through Phase 5
requirement→implementation rows (its former "Phase 1" title was stale). It
stays a map, not a status report — live build state is still derived from
`scripts/status.sh`, never written here.

The requirements baseline is **outside the repo**, at
`C:\Users\CTYea\awsx_docs\` (7 `.docx`). Those files are authoritative; the
PDFs beside them are duplicates and `_awsx_extract/*.txt` is a derived
extraction. Quote the `.docx`, never the derivations.

## Environment

Windows 10 host; the terminal is **bash (git-bash/MSYS)**, not PowerShell.
There is no PHP, Composer or mysql client on the host — everything runs through
`docker compose exec -T app`. Two failure modes worth knowing before your first
command, because both fail *silently*:

- **phpstan needs `--memory-limit=1G`.** The container's 128M default OOMs and
  reports a fake "severe errors" result that looks like a code failure.
- **`docker compose exec` does not inherit the host shell's environment.** An
  exported `TEST_DB_DSN` is ignored and the run quietly uses the compose-file
  value — which is how "isolated database" runs became no-ops. Pass it inline
  with `-e`, then prove isolation by counting tables in the ISO database.

The repo must stay on `C:` — `E:` is removable exFAT and Docker mounts it
silently empty.
