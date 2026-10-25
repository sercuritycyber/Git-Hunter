# Git-Hunter

Git-Hunter is a headless GitHub repository triage pipeline for an isolated worker VM. It discovers small, recently active repositories, queues them in Turso/libSQL storage, analyzes raw sources in memory, and exposes reports for human review.

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .

export TURSO_DATABASE_URL=libsql://your-database.turso.io
export TURSO_AUTH_TOKEN=your_turso_token
# GitHub_TOKEN is optional, but increases API rate limits.
export GITHUB_TOKEN=your_token
git-hunter discover --query 'pushed:>2026-01-01 language:Python' --limit 10
git-hunter worker --once
git-hunter dashboard
```

Run `git-hunter` or `git-hunter dashboard` and open `http://127.0.0.1:8080`. The localhost Admin Center starts the Wanderer spider, worker, and web server concurrently. It provides Overview, Live Analysis, Review Queue, Targets, and Settings dashboards. Use Settings to enter a GitHub token and Turso connection details; secrets are held in process memory and are not written to queue or report records. The Live Analysis view shows the repository being fetched, analysis stage, files discovered, source preview, and current codebase. Start/stop controls pause and resume crawling and scanning. Markdown reports are stored in the Turso `results` table. Set `COLD_STORAGE_PATH=/mnt/quarantine` for the Proxmox cold-storage mount.

## Current scope

- GitHub Search API discovery with author repositories and forks added to the queue.
- Turso/libSQL `queue` and `results` tables with queue deduplication and human review states.
- Continuous Wanderer discovery using recent CVE, PoC, and Python pushes, plus repository-owner follower/following pivots.
- Admin Center control APIs for runtime configuration, credentials, lifecycle controls, live analysis, queue metrics, and activity history.
- Five operational dashboards with three-second runtime telemetry polling and live repository/codebase progress.
- Deterministic Python AST data-flow checks for high-entropy Base64 payloads reaching execution or network sinks.
- Malformed Python is retained as a +50 anomaly finding instead of being silently discarded.
- GitHub Search calls are paced at 6.5 seconds, with `Retry-After` and `x-ratelimit-reset` backoff handling.
- Optional Claude CLI enrichment with a five-second timeout and failure isolation.
- JSON API and lightweight review dashboard. A malicious confirmation, rather than the worker, streams the repository zipball into `COLD_STORAGE_PATH` (default `/mnt/quarantine`).

The worker analyzes Python files fetched through the GitHub tree and raw-content APIs; it never clones or snapshots code during analysis. Bash and JavaScript analyzers are intentionally separate follow-up slices so each parser can be tested independently.