from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import libsql_client

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS queue (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'scanning', 'completed', 'failed', 'malicious_confirmed', 'safe')),
    priority INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS results (
    repo_id INTEGER PRIMARY KEY REFERENCES queue(id),
    anomaly_score INTEGER NOT NULL CHECK (anomaly_score BETWEEN 0 AND 100),
    raw_json TEXT NOT NULL,
    markdown_report TEXT NOT NULL
);
"""


class Store:
    """Turso/libSQL state manager."""

    _instances: dict[str, Store] = {}

    def __new__(cls, path: str | Path = "data/git_hunter.db") -> Store:
        key = os.getenv("TURSO_DATABASE_URL") or str(Path(path).expanduser().resolve())
        if key not in cls._instances:
            cls._instances[key] = super().__new__(cls)
        return cls._instances[key]

    def __init__(self, path: str | Path = "data/git_hunter.db") -> None:
        if getattr(self, "_initialized", False):
            return
        self.path = Path(path).expanduser()
        url = os.getenv("TURSO_DATABASE_URL") or f"file:{self.path.resolve()}"
        token = os.getenv("TURSO_AUTH_TOKEN")
        self.client = libsql_client.create_client_sync(url, auth_token=token)
        execute_batch = getattr(self.client, "execute_batch", None)
        if execute_batch:
            execute_batch(SCHEMA)
        else:
            statements = [statement.strip() for statement in SCHEMA.split(";") if statement.strip()]
            self.client.batch(statements)
        self._initialized = True

    @staticmethod
    def _rows(result: Any) -> list[dict[str, Any]]:
        columns = list(result.columns)
        return [dict(zip(columns, row)) for row in result.rows]

    def _one(self, result: Any) -> dict[str, Any] | None:
        rows = self._rows(result)
        return rows[0] if rows else None

    def enqueue(self, url: str, full_name: str, priority: int) -> bool:
        result = self.client.execute(
            "INSERT OR IGNORE INTO queue(url, full_name, priority) VALUES (?, ?, ?)",
            (url, full_name, priority),
        )
        return result.rows_affected == 1

    def contains_url(self, url: str) -> bool:
        return self._one(self.client.execute("SELECT id FROM queue WHERE url=? LIMIT 1", (url,))) is not None

    def claim_next(self) -> dict[str, Any] | None:
        row = self._one(self.client.execute(
            "SELECT * FROM queue WHERE status='pending' ORDER BY priority DESC LIMIT 1"
        ))
        if row:
            self.client.execute("UPDATE queue SET status='scanning' WHERE id=?", (row["id"],))
            row = self._one(self.client.execute("SELECT * FROM queue WHERE id=?", (row["id"],)))
        return row

    def save_result(self, repo_id: int, result: dict[str, Any], markdown_report: str) -> None:
        self.client.execute(
            "INSERT OR REPLACE INTO results(repo_id, anomaly_score, raw_json, markdown_report) VALUES (?, ?, ?, ?)",
            (repo_id, result["anomaly_score"], json.dumps(result), markdown_report),
        )
        self.client.execute("UPDATE queue SET status='completed' WHERE id=?", (repo_id,))

    def fail(self, repo_id: int) -> None:
        self.client.execute("UPDATE queue SET status='failed' WHERE id=?", (repo_id,))

    def review(self, repo_id: int, status: str) -> None:
        if status not in {"malicious_confirmed", "safe"}:
            raise ValueError("status must be malicious_confirmed or safe")
        self.client.execute("UPDATE queue SET status=? WHERE id=?", (status, repo_id))

    def reports(self) -> list[dict[str, Any]]:
        return self._rows(self.client.execute(
            "SELECT q.id, q.url, q.full_name, q.status, r.anomaly_score, r.raw_json, r.markdown_report FROM queue q JOIN results r ON r.repo_id=q.id WHERE r.anomaly_score > 50 AND q.status NOT IN ('safe', 'malicious_confirmed') ORDER BY r.anomaly_score DESC"
        ))

    def report(self, repo_id: int) -> dict[str, Any] | None:
        return self._one(self.client.execute(
            "SELECT q.id, q.url, q.full_name, q.status, r.anomaly_score, r.raw_json, r.markdown_report FROM queue q JOIN results r ON r.repo_id=q.id WHERE q.id=?",
            (repo_id,),
        ))

    def queue_item(self, repo_id: int) -> dict[str, Any] | None:
        return self._one(self.client.execute("SELECT * FROM queue WHERE id=?", (repo_id,)))
