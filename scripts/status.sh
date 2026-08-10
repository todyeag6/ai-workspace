#!/usr/bin/env bash
# scripts/status.sh — print the CURRENT build state, derived from git.
#
# WHY THIS EXISTS
#   Hand-maintained status prose in docs/ goes stale the moment a commit lands,
#   and stale prose has repeatedly caused wrong state claims at session start
#   (a doc said "P2-T5 NOT YET PUSHED" long after it was pushed; another still
#   framed the repo as "Phase 0 -> Phase 1" at Phase 3). Prose cannot be kept
#   honest by discipline alone, so status is DERIVED here instead of retyped.
#
# CONTRACT
#   Every number and hash below comes from git or a live command at the moment
#   you run it. Nothing is cached, nothing is remembered. If it disagrees with
#   a markdown file, THIS is right and the markdown is stale.
#
#   Run it, don't quote it: `bash scripts/status.sh`
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "=============================================================="
echo " AIWEBSCAPES PLATFORM — LIVE STATE  ($(date -u +%Y-%m-%dT%H:%MZ))"
echo "=============================================================="
echo
echo "-- Repository ------------------------------------------------"
printf '  branch      : %s\n' "$(git rev-parse --abbrev-ref HEAD)"
printf '  HEAD        : %s\n' "$(git rev-parse --short HEAD)"
printf '  remote      : %s\n' "$(git remote get-url origin 2>/dev/null || echo '<none>')"

DIRTY=$(git status --porcelain | wc -l | tr -d ' ')
printf '  working tree: %s\n' "$([ "$DIRTY" -eq 0 ] && echo 'clean' || echo "$DIRTY modified path(s)")"

# Two-dot range = AHEAD. The three-dot `--left-only` form reports BEHIND and
# reads 0 even when unpushed — a false "already pushed" signal.
if git rev-parse --verify origin/main >/dev/null 2>&1; then
  AHEAD=$(git rev-list --count origin/main..HEAD)
  printf '  unpushed    : %s commit(s)\n' "$AHEAD"
  [ "$AHEAD" -gt 0 ] && git log --oneline origin/main..HEAD | sed 's/^/                /'
else
  echo "  unpushed    : <no origin/main ref; run git fetch>"
fi
echo

echo "-- Delivered tasks (git log is the record) -------------------"
# Feature commits only: the task ids live in the subjects, so the log IS the
# task table. No second copy to fall out of date.
git log --oneline --reverse --grep='^feat' -E --format='  %h  %s' origin/main 2>/dev/null \
  || git log --oneline --reverse --grep='^feat' -E --format='  %h  %s'
echo

echo "-- Latest activity -------------------------------------------"
git log -5 --format='  %h  %ad  %s' --date=short
echo

echo "-- Verify gates (run these; do not quote a remembered result) -"
cat <<'GATES'
  Focused (dev loop, ~2 min):
    bash "C:/Users/CTYea/AppData/Local/hermes/skills/software-development/\
aiwebscapes-platform-build/scripts/hermes-verify-task.sh" <FilterName> config/security

  Full certification (~6 min, isolated CREATE-only DB):
    phpstan : docker compose exec -T app vendor/bin/phpstan analyse --no-progress --memory-limit=1G
    phpcs   : docker compose exec -T app vendor/bin/phpcs --standard=phpcs.xml -n src tests config/security
    phpunit : docker compose exec -T -e TEST_DB_DSN="mysql:host=db;dbname=<unique_iso>;charset=utf8mb4" \
                app vendor/bin/phpunit

  phpstan REQUIRES --memory-limit=1G (container default 128M OOMs and reports a
  fake "severe errors" failure). `docker compose exec` does NOT inherit host env:
  pass TEST_DB_DSN INLINE with -e, then PROVE isolation by counting tables in the
  ISO DB. An exported value is silently ignored.
GATES
echo

echo "-- Requirements baseline -------------------------------------"
echo "  C:\\Users\\CTYea\\awsx_docs\\*.docx  (7 files, outside the repo)"
echo "  The .docx are authoritative. The PDFs are duplicates and the"
echo "  _awsx_extract/*.txt are a derived extraction — never quote those."
echo
echo "=============================================================="
