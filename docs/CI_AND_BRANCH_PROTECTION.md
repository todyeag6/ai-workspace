# CI and branch protection — standing constraints

Reference, not status. Run `bash scripts/status.sh` for current state.

Extracted verbatim (2026-08-10) from the old `HANDOFF.md` §9, which was
otherwise stale status prose. The findings below are still in force: they
describe GitHub plan-tier limits, not a moment in the build.

## The local gate is the source of truth

`.github/workflows/ci.yml` runs the same six gates as `scripts/ci-local.sh` on
a GitHub-hosted runner. On a **free private repo GitHub allocates runners
sparsely**, so a run can sit `queued` for a long time — or never be scheduled.
A queued run is a plan-tier scheduler artifact, **not** a code defect and not a
failure. Treat `scripts/ci-local.sh` as the authoritative CI proof.

A critical fix landed in `9eb9fa1`: the MySQL service container was labelled
`mysql` while the PHP DSNs connect to host `db`, papered over with a fragile
`echo 127.0.0.1 db redis | sudo tee /etc/hosts` step. Per the GitHub Actions
documentation ("the hostname of the service container is the label you
configure"), the service is now named `db` to match the DSN and the
`/etc/hosts` hack is gone. The pre-fix runs failed with run=failure /
job=cancelled / 0 steps / no logs — consistent with an unreachable service.

**Parity fix** (`0d79748`): the phpstan step in `ci.yml` was missing
`--memory-limit=1G` and the phpcs step was missing `-n`. Without these, CI diverged
from `scripts/ci-local.sh`: phpstan OOM'd at the 128M default and reported a fake
"severe errors", and phpcs failed on accepted line-length warnings. Both flags are
now in `ci.yml`, matching `ci-local.sh`. The local-script pitfall (needing `-n`
under `set -euo pipefail`) is still relevant for anyone running `ci-local.sh` by hand,
but the CI-vs-local parity gap is closed.

## SEC-008 branch protection is BLOCKED by the plan tier — OPEN, not skipped

Both the legacy branch-protection API and the rulesets API return
`403 "Upgrade to GitHub Pro or make this repository public to enable this
feature."` for this private Free repo. Confirmed against GitHub's own
documentation: protected branches and rulesets are available on public repos,
and on private repos only with Pro, Team, or Enterprise.

So SEC-008 (require PR + review + status check before merge; block force-push
and delete) **cannot currently be enabled**. The options:

1. Make the repo public — protection works free, but the code is proprietary.
2. Upgrade to GitHub Pro (~$4/mo) — stays private and unlocks rulesets.
3. Stay private and free — CI still runs on push/PR, but the *merge gate*
   cannot be enforced.

**Decision (owner, 2026-08-06): stay private and free.** SEC-008 is therefore
recorded as **OPEN, blocked by plan tier** — explicitly documented rather than
silently skipped. Revisit if the repo ever goes public or the plan changes.
