#!/usr/bin/env bash
# Bring the stack up detached and poll until the db healthcheck reports healthy.
#
# P4-T4: accepts --size {small|medium|large} (default medium) and an optional
# --deploy-config <path>. --dry-run prints the resolved selection and exits
# without touching Docker (used by tests). Re-running is idempotent.
set -u
cd "$(dirname "$0")/.." || exit 1

SIZE="medium"
DRY_RUN=0
DEPLOY_CONFIG=""
prev=""

for arg in "$@"; do
  case "$prev" in
    --size) SIZE="$arg" ;;
    --deploy-config) DEPLOY_CONFIG="$arg" ;;
  esac
  case "$arg" in
    --size=*) SIZE="${arg#*=}" ;;
    --deploy-config=*) DEPLOY_CONFIG="${arg#*=}" ;;
    --dry-run) DRY_RUN=1 ;;
    --size|--deploy-config) : ;; # value arrives in the next iteration
    *) : ;;
  esac
  prev="$arg"
done

case "$SIZE" in
  small|medium|large) : ;;
  *) echo "INVALID_SIZE=$SIZE"; exit 2 ;;
esac

if [ "$DRY_RUN" -eq 1 ]; then
  echo "DRY_RUN=1"
  echo "SIZE=$SIZE"
  [ -n "$DEPLOY_CONFIG" ] && echo "DEPLOY_CONFIG=$DEPLOY_CONFIG"
  exit 0
fi

docker compose up -d
rc=$?
echo "up_exit_code=$rc"

for i in $(seq 1 60); do
  status=$(docker inspect --format '{{.State.Health.Status}}' \
    "$(docker compose ps -q db)" 2>/dev/null)
  echo "poll $i: db=$status"
  if [ "$status" = "healthy" ]; then
    echo "DB_HEALTHY_AFTER=${i}_polls"
    exit 0
  fi
  sleep 3
done

echo "DB_NEVER_BECAME_HEALTHY"
exit 1
