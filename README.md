# Git-Hunter

Git-Hunter is a local-first GitHub repository triage pipeline. It discovers small, recently active repositories, queues them in SQLite (compatible with a Turso/libSQL migration path), runs deterministic Python analysis, and exposes reports for human review.

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

Open `http://127.0.0.1:8080`. The local database is `data/git_hunter.db`; reports are written to `reports/`.

## Current scope

- GitHub Search API discovery with author repositories and forks added to the queue.
- SQLite queue with atomic claims, scan results, and human review overrides.
- Deterministic Python AST checks for execution, network, decoding, and dynamic-import sinks.
- Optional Claude CLI enrichment with a strict timeout and failure isolation.
- JSON API and lightweight review dashboard. Malicious confirmation snapshots the repository as a zipball when `GITHUB_TOKEN` is configured.

The worker currently analyzes Python files fetched from a repository zipball. Bash and JavaScript analyzers are intentionally separate follow-up slices so each parser can be tested independently.