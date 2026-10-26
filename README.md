# Git-Hunter

Git-Hunter is a headless GitHub repository triage pipeline for an isolated worker VM. It discovers small, recently active repositories, queues them in Turso/libSQL storage, analyzes raw sources in memory, and exposes reports for human review.

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .

git-hunter dashboard
```

Run `git-hunter` or `git-hunter dashboard` and open `http://127.0.0.1:8080`. The localhost Admin Center opens stopped, so no secret is needed in the command line or shell history. Use Settings to enter a GitHub token and optional Turso URL/auth token, then use the Start system control. Secrets are held in process memory and are not written to queue or report records. The localhost Admin Center provides Overview, Live Analysis, Review Queue, Targets, and Settings dashboards. The Live Analysis view shows the repository being fetched, analysis stage, files discovered, source preview, and current codebase. Markdown reports are stored in the configured database. Set `COLD_STORAGE_PATH=/mnt/quarantine` for the Proxmox cold-storage mount.

## Kali Linux service mode

For a persistent local service, install the example unit and run the dashboard under systemd:

```bash
sudo useradd --system --home /opt/git-hunter --shell /usr/sbin/nologin git-hunter
sudo install -d -o git-hunter -g git-hunter /opt/git-hunter /var/lib/git-hunter /etc/git-hunter
sudo install -m 0644 contrib/git-hunter.service /etc/systemd/system/git-hunter.service
sudo systemctl daemon-reload
sudo systemctl enable --now git-hunter
systemctl status git-hunter
```

Set `GITHUB_TOKEN`, `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, and `COLD_STORAGE_PATH` in `/etc/git-hunter/git-hunter.env`. The unit binds the dashboard to loopback; use an authenticated reverse proxy if remote access is required.

## Current scope

- GitHub Search API discovery with author repositories and forks added to the queue.
- Turso/libSQL `queue` and `results` tables with queue deduplication and human review states.
- Continuous Wanderer discovery using recent CVE, PoC, and Python pushes, plus repository-owner follower/following pivots.
- Randomized discovery mode rotates CVE, PoC, and Python search seeds and GitHub result pages; pending queue claims are also random so consecutive scans do not always select the same repository path.
- Admin Center control APIs for runtime configuration, credentials, lifecycle controls, live analysis, queue metrics, and activity history.
- Five operational dashboards with three-second runtime telemetry polling and live repository/codebase progress.
- Deterministic Python AST data-flow checks for high-entropy Base64 payloads reaching execution or network sinks.
- Malformed Python is retained as a +50 anomaly finding instead of being silently discarded.
- GitHub Search calls are paced at 6.5 seconds, with `Retry-After` and `x-ratelimit-reset` backoff handling.
- Optional Claude CLI enrichment with a five-second timeout and failure isolation.
- JSON API and lightweight review dashboard. A malicious confirmation, rather than the worker, streams the repository zipball into `COLD_STORAGE_PATH` (default `/mnt/quarantine`).

The worker analyzes Python files fetched through the GitHub tree and raw-content APIs; it never clones or snapshots code during analysis. Bash and JavaScript analyzers are intentionally separate follow-up slices so each parser can be tested independently.