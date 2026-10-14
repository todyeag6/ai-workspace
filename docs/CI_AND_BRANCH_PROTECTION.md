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

## SEC-008 branch protection is GREEN — enforced on `main` (2026-10-14)

The repo was made **public** (`visibility: public`, verified via `GET /repos/todyeag6/ai-workspace`).
GitHub's own documentation states that branch protection is available on public repos for free:
https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches

The legacy branch-protection API was called on 2026-10-14 and returned **HTTP 200**.
Verified live via `GET .../branches/main/protection`:

- `required_pull_request_reviews.required_approving_review_count: 1` — PR + review required
- `required_status_checks.strict: true`, `contexts: ["quality-gate"]` — CI must pass
- `allow_force_pushes: False` — force-push blocked
- `allow_deletions: False` — branch deletion blocked
- `enforce_admins: False` — admins retain direct-push (avoids lockout during transition)

SEC-008 is **no longer blocked**. The `403 "Upgrade to GitHub Pro"` error from the
private-repo era does not apply. Changes to `main` now flow through PRs with a
required review and a passing `quality-gate` status check.
