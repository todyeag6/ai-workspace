# Aiwebscapes Platform — Run It Locally (KISS)

## What this is, in one breath
A **PHP 8.3** multi-tenant backend. You never install PHP on your laptop — the
whole thing runs inside Docker. You "use" it by running its **test suite** and
its **quality gates**, plus one optional demo dashboard page. There is no big
website to click around in: this is a backend you *prove* with tests.

## You only need two tools
1. **Docker Desktop** (Linux containers enabled).
2. **git-bash** (you're on Windows 10 — use the Git Bash terminal, *not* PowerShell).

That's it. No PHP, no Composer, no MySQL on your machine.

## The mental model (three bubbles)
```
   YOUR LAPTOP          DOCKER CONTAINERS        QUALITY GATES
   you edit files  -->  code runs here      -->  prove it's green
   src/ tests/          app db redis              scripts/ci-local.sh
   compose.yaml
```
All three have to meet. You edit on the laptop, the code runs in Docker, and
the gates confirm it works.

## 1. Get it running (two commands)
```bash
git clone <repo-url>
cd aiwebscapes-platform
docker compose up -d          # starts app + db + redis; waits for db healthy
```
That is the whole install. The `app` container stays up as a **workspace** —
you drive it with:
```bash
docker compose exec -T app <command>
```

## 2. Run the tests
Tests run against a **real MySQL 8** database (not a fake one). The test
harness creates the test DB, applies every migration, and rolls each test back
automatically — you manage none of that.
```bash
docker compose exec -T \
  -e TEST_DB_DSN="mysql:host=db;dbname=aiwebscapes_test;charset=utf8mb4" \
  app vendor/bin/phpunit
```
*(The `-e TEST_DB_DSN=...` is required — see Gotcha #3.)*

## 3. Run the quality gates
```bash
bash scripts/ci-local.sh
```
Six checks, in order: PSR-12 lint → PHPStan (static analysis) → dependency
audit → SBOM → secret scan → the tests. All six green = a green build.

## 4. Optional: the demo dashboard
One page exists to show the UI (`public/index.php`). From inside the app
container:
```bash
docker compose exec -T app php -S 0.0.0.0:8080 -t public
```
Then open `http://localhost:8080`. The `app` service publishes **no port by
default**, so to reach it from your browser, add `ports: ['8080:8080']` under
`app` in `compose.yaml` first (or just run it to confirm the page serves).

## 5. CLI scripts worth reading
Run each *inside* the container (`docker compose exec -T app php scripts/...`):
- `migrate.php --dsn=<dsn>` — apply migrations (no default DSN; you type it).
- `backup.php` / `restore.php` — database snapshots.
- `deploy-client.php` — client-deploy helper.

## Gotchas that used to waste your afternoon (now fixed / understood)
1. **PHPStan OOMs at the container's default 128M** and prints a fake
   "severe errors" that looks like a code bug. ✅ **Fixed:** `scripts/ci-local.sh`
   now runs PHPStan with `--memory-limit=1G`. If you run phpstan by hand, always
   add that flag.
2. **`.env` was never loaded into the containers.** ✅ **Fixed:** `compose.yaml`
   now has `env_file: .env` (optional, won't break a fresh clone). The hardcoded
   DSNs in `environment:` still win, so nothing else changes.
3. **`docker compose exec` does NOT inherit your host shell's environment.** If
   you `export TEST_DB_DSN` on the laptop, the container ignores it. Always pass
   it inline (`exec -T -e TEST_DB_DSN=...`) — that's why step 2 shows `-e`.
4. **Secret scan over an empty mount = false pass.** Already guarded inside
   `ci-local.sh` (it refuses to trust a scan under ~20 KB). No action needed.

## Do I need an APP_KEY?
**No — not for testing or learning.** The test suite, the quality gates, and the
demo dashboard all run without it. `APP_KEY` is read *only* by the **legacy boot
path** (`legacy/config/app.php`), which fails closed on purpose (FR-CONF-002) if
a required key is missing.

If you *do* want to try that legacy path, copy the example and set any long
random string:
```bash
cp .env.example .env
# edit .env:  APP_KEY=any-long-random-string
```
Thanks to Gotcha #2, that `.env` is now picked up by the containers.

## "Is it actually working?"
```bash
bash scripts/status.sh
```
It prints live state straight from git. Trust the script over any written doc.
