from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


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
    """SQLite state manager with a Turso/libSQL-compatible SQL surface."""

    _instances: dict[str, Store] = {}

    def __new__(cls, path: str | Path = "data/git_hunter.db") -> Store:
        key = str(Path(path).expanduser().resolve())
        if key not in cls._instances:
            cls._instances[key] = super().__new__(cls)
        return cls._instances[key]

    def __init__(self, path: str | Path = "data/git_hunter.db") -> None:
        if getattr(self, "_initialized", False):
            return
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self.connection.commit()
        self._initialized = True

    def enqueue(self, url: str, full_name: str, priority: int) -> bool:
        cursor = self.connection.execute(
            "INSERT OR IGNORE INTO queue(url, full_name, priority) VALUES (?, ?, ?)",
            (url, full_name, priority),
        )
        self.connection.commit()
        return cursor.rowcount == 1

    def claim_next(self) -> sqlite3.Row | None:
        self.connection.execute("BEGIN IMMEDIATE")
        row = self.connection.execute(
            "SELECT * FROM queue WHERE status='pending' ORDER BY priority DESC LIMIT 1"
        ).fetchone()
        if row:
            self.connection.execute("UPDATE queue SET status='scanning' WHERE id=?", (row["id"],))
            row = self.connection.execute("SELECT * FROM queue WHERE id=?", (row["id"],)).fetchone()
        self.connection.commit()
        return row

    def save_result(self, repo_id: int, result: dict[str, Any], markdown_report: str) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO results(repo_id, anomaly_score, raw_json, markdown_report) VALUES (?, ?, ?, ?)",
            (repo_id, result["anomaly_score"], json.dumps(result), markdown_report),
        )
        self.connection.execute("UPDATE queue SET status='completed' WHERE id=?", (repo_id,))
        self.connection.commit()

    def fail(self, repo_id: int) -> None:
        self.connection.execute("UPDATE queue SET status='failed' WHERE id=?", (repo_id,))
        self.connection.commit()

    def review(self, repo_id: int, status: str) -> None:
        if status not in {"malicious_confirmed", "safe"}:
            raise ValueError("status must be malicious_confirmed or safe")
        self.connection.execute("UPDATE queue SET status=? WHERE id=?", (status, repo_id))
        self.connection.commit()

    def reports(self) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT q.id, q.url, q.full_name, q.status, r.anomaly_score, r.raw_json, r.markdown_report FROM queue q JOIN results r ON r.repo_id=q.id WHERE r.anomaly_score > 50 AND q.status NOT IN ('safe', 'malicious_confirmed') ORDER BY r.anomaly_score DESC"
        ).fetchall()

    def report(self, repo_id: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT q.id, q.url, q.full_name, q.status, r.anomaly_score, r.raw_json, r.markdown_report FROM queue q JOIN results r ON r.repo_id=q.id WHERE q.id=?",
            (repo_id,),
        ).fetchone()

    def queue_item(self, repo_id: int) -> sqlite3.Row | None:
        return self.connection.execute("SELECT * FROM queue WHERE id=?", (repo_id,)).fetchone()
