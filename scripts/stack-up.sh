#!/usr/bin/env bash
# Bring the stack up detached and poll until the db healthcheck reports healthy.
set -u
cd /c/Users/CTYea/dev/aiwebscapes-platform || exit 1

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
