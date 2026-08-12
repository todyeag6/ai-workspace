#!/usr/bin/env bash
#
# scripts/ci-local.sh - Phase 0 quality gate, run locally (SEC-007, SEC-008).
#
# This is the authoritative proof that the CI gates pass while the project has
# no GitHub remote. .github/workflows/ci.yml runs the same checks on a runner
# the moment a remote exists; this script runs them against the local Docker
# stack today.
#
# Gates, in order:
#   1. PSR-12 lint          phpcs   (src/, tests/)
#   2. Static analysis      phpstan (level 8, src/ + tests/)
#   3. Dependency vulns     composer audit
#   4. SBOM                 CycloneDX (composer plugin) -> sbom.xml
#   5. Secret scan          gitleaks (host Docker, .gitleaks.toml allowlist)
#   6. Tests                phpunit
#
# Usage:  bash scripts/ci-local.sh          (works from ANY working directory)
#
# Requirements: the compose stack must already be running. This script never
# builds, starts or stops containers, and never mutates composer.json.
#
set -euo pipefail

# --- Always operate from the repository root, whatever the caller's CWD -------
if REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null)"; then
    :
else
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "$REPO_ROOT"

# Native Windows path for Docker bind mounts (MSYS/git-bash); plain pwd elsewhere.
REPO_MOUNT="$(pwd -W 2>/dev/null || pwd)"

D="docker compose exec -T app"
GITLEAKS_IMAGE="ghcr.io/gitleaks/gitleaks:latest"
step=0

banner() {
    step=$((step + 1))
    printf '\n== %d/6 %s ==\n' "$step" "$1"
}

fail() {
    printf '\nFAILED: %s\n' "$1" >&2
    exit 1
}

echo "repo root : $REPO_ROOT"
echo "mount path: $REPO_MOUNT"

# --- Preflight: the stack must already be up ----------------------------------
if ! docker compose ps --status=running --services 2>/dev/null | grep -qx 'app'; then
    fail "compose service 'app' is not running. Start the existing containers with:
         docker start aiwebscapes-platform-db-1 aiwebscapes-platform-redis-1 aiwebscapes-platform-app-1"
fi

# --- 1. PSR-12 ----------------------------------------------------------------
# Gate on ERRORS only: the project standard is "0 phpcs errors". Line-length
# warnings (Generic.Files.LineLength) are accepted and have been since Phase 0;
# without -n the warning exit code aborts this script at gate 1 and the "6/6"
# banner is never reached (a false-fail of the CI proof itself).
banner "PSR-12 (phpcs, errors only)"
$D vendor/bin/phpcs --standard=phpcs.xml -n src tests

# --- 2. Static analysis -------------------------------------------------------
banner "PHPStan level 8"
# --memory-limit=1G is REQUIRED: the app container's php.ini default is 128M,
# which OOMs PHPStan on the real src+tests+build tree and reports a fake
# "severe errors" result that looks like a code failure (docs/HANDOFF.md).
$D vendor/bin/phpstan analyse --no-progress --memory-limit=1G

# --- 3. Dependency vulnerabilities --------------------------------------------
banner "Dependency vulnerabilities (composer audit)"
$D composer audit

# --- 4. SBOM ------------------------------------------------------------------
# The tool is installed once as a setup step:
#   docker compose exec -T app composer require --dev cyclonedx/cyclonedx-php-composer
# This script only RUNS it - it must never mutate composer.json.
banner "SBOM (CycloneDX)"
if ! $D composer list --raw 2>/dev/null | grep -qi '^CycloneDX:make-sbom'; then
    fail "CycloneDX composer plugin is not installed. Install it once with:
         docker compose exec -T app composer require --dev cyclonedx/cyclonedx-php-composer
         (this script deliberately does NOT modify composer.json)"
fi
$D composer CycloneDX:make-sbom \
    --output-format=XML \
    --output-file=sbom.xml \
    --spec-version=1.6 \
    --validate
[[ -s sbom.xml ]] || fail "sbom.xml was not produced or is empty."
echo "sbom.xml: $(wc -c < sbom.xml) bytes, $(grep -c '<component ' sbom.xml) components"

# --- 5. Secret scan -----------------------------------------------------------
banner "Secret scan (gitleaks)"

# Mount sanity FIRST: a silently empty bind mount scans ~0 bytes, finds nothing
# and exits 0 - a false pass. Probe the exact mount gitleaks will use and
# require known repository files to be visible inside the container.
if ! docker run --rm --entrypoint sh -v "$REPO_MOUNT":/repo "$GITLEAKS_IMAGE" \
        -c 'test -f /repo/composer.json && test -f /repo/.gitleaks.toml' >/dev/null 2>&1; then
    fail "the bind mount '$REPO_MOUNT' -> /repo is empty or unreadable inside Docker.
         A scan over an empty mount reports 'no leaks found' and exits 0 (false pass)."
fi
echo "mount sanity: /repo contains composer.json and .gitleaks.toml"

gitleaks_rc=0
gitleaks_out="$(docker run --rm -v "$REPO_MOUNT":/repo "$GITLEAKS_IMAGE" \
    dir /repo --redact --no-banner --config=/repo/.gitleaks.toml 2>&1)" || gitleaks_rc=$?
echo "$gitleaks_out"

# Guard against a silently empty bind mount: an empty mount scans ~0 bytes and
# exits 0, which would be a false pass.
scanned_bytes="$(printf '%s\n' "$gitleaks_out" \
    | sed -n 's/.*scanned ~\([0-9][0-9]*\) bytes.*/\1/p' | tail -n 1)"
if [[ -z "${scanned_bytes:-}" ]]; then
    fail "could not determine how many bytes gitleaks scanned - refusing to trust the result."
fi
if (( scanned_bytes < 20000 )); then
    fail "gitleaks scanned only ${scanned_bytes} bytes - suspiciously small, treat as a false pass."
fi
echo "scan volume: gitleaks scanned ${scanned_bytes} bytes"
if (( gitleaks_rc != 0 )); then
    fail "gitleaks reported findings (exit ${gitleaks_rc}). Review them - do not blindly allowlist."
fi

# --- 6. Tests -----------------------------------------------------------------
banner "Tests (phpunit)"
$D vendor/bin/phpunit

printf '\nALL LOCAL CI GATES PASSED\n'
