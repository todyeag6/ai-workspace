# Aiwebscapes Platform — AGENTS.md

PHP (Laravel-style) + MySQL + Redis platform. Dockerized dev stack in `compose.yaml`.
Authoritative architecture/compliance posture is encoded in `compose.yaml` comments and the repo's
audit docs (`AUDIT-REPORT.md`, `docs/`) — trust those over chat summary.

## Dev stack (Docker Compose)
- Bring up: `docker compose up -d` (app/build via Dockerfile; `command: sleep infinity` for a live shell).
- `app` mounts `.` at `/app`, `working_dir: /app`, network `app_net` (production business systems).
- **DB:** MySQL 8, **host port `3307` → container `3306`** (`DB_DSN` = `mysql:host=db;dbname=aiwebscapes;charset=utf8mb4`).
  Test DB: `aiwebscapes_test`. **Redis:** `tcp://redis:6379`.
- Local AI: `AI_LOCAL_BASE_URL=http://host.docker.internal:11434/v1` (host Ollama). In-stack `openviking`
  service reaches host OpenViking at `http://host.docker.internal:1933`.
- Copy `.env.example` → `.env`; never commit a real `.env`. `APP_KEY` is required or legacy boot fails.

## Security topology (do not weaken)
- `SFR-SELF-001` deny-by-default network segmentation: `app_net` (app/db/redis/openviking/ollama) vs
  `scanner_net` (isolated, attaches to **NO** production service). `ScannerInfrastructureGuard` enforces
  that a scan scope cannot reach db/redis.

## OFF-LIMITS — do NOT touch without explicit scope
- The running production/hybrid stack (app/redis/db-1) is **NOT** in this repo's scope. Do not inspect,
  stop, remove, or `docker container prune` it. Blanket prune is forbidden.
- Example/placeholder service names mentioned in conversation are **NOT** targets to investigate and must
  not be conflated with this stack.

## Quality gates (run before declaring done)
- Static: `phpstan` (config `phpstan.neon`, pass `--memory-limit=1G`), `phpcs`
  (`phpcs.xml`, pass `-n` for errors-only), `gitleaks` (`.gitleaks.toml`).
- Tests: `phpunit` (`phpunit.xml`). Migrations in `migrations/`.
- CI parity: `.github/workflows/ci.yml` runs the same 6 gates on GitHub-hosted
  runners with `--memory-limit=1G` on phpstan and `-n` on phpcs (parity fix
  committed `0d79748`). If flags diverge, run `bash scripts/ci-local.sh` for the
  authoritative local proof.
