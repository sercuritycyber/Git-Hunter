# Git-Hunter

Git-Hunter is a local-first GitHub repository triage pipeline for an isolated worker VM. It discovers small, recently active repositories, queues them in SQLite/libSQL-compatible storage, analyzes raw Python sources in memory, and exposes reports for human review.

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .

# GitHub_TOKEN is optional, but increases API rate limits.
export GITHUB_TOKEN=your_token
git-hunter discover --query 'pushed:>2026-01-01 language:Python' --limit 10
git-hunter worker --once
git-hunter dashboard
```

Open `http://127.0.0.1:8080`. The local database is `data/git_hunter.db`; Markdown reports are written to `reports/`. Set `COLD_STORAGE_PATH=/mnt/quarantine` for the Proxmox cold-storage mount.

## Current scope

- GitHub Search API discovery with author repositories and forks added to the queue.
- SQLite/libSQL-compatible queue with atomic claims, scan results, provenance, and human review states.
- Deterministic Python AST data-flow checks for high-entropy Base64 payloads reaching execution or network sinks.
- Malformed Python is retained as a +50 anomaly finding instead of being silently discarded.
- GitHub Search calls are paced at 6.5 seconds, with `Retry-After` and `x-ratelimit-reset` backoff handling.
- Optional Claude CLI enrichment with a five-second timeout and failure isolation.
- JSON API and lightweight review dashboard. A malicious confirmation, rather than the worker, streams the repository zipball into `COLD_STORAGE_PATH` (default `/mnt/quarantine`).

The worker analyzes Python files fetched through the GitHub tree and raw-content APIs; it never clones or snapshots code during analysis. Bash and JavaScript analyzers are intentionally separate follow-up slices so each parser can be tested independently.