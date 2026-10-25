from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS repos_queue (
    id INTEGER PRIMARY KEY,
    full_name TEXT NOT NULL UNIQUE,
    html_url TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'analyzing', 'completed', 'failed')),
    added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY,
    repo_full_name TEXT NOT NULL REFERENCES repos_queue(full_name),
    anomaly_score INTEGER NOT NULL CHECK (anomaly_score BETWEEN 0 AND 100),
    findings_json TEXT NOT NULL,
    markdown TEXT NOT NULL,
    ai_summary TEXT,
    scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS human_review (
    id INTEGER PRIMARY KEY,
    repo_full_name TEXT NOT NULL UNIQUE REFERENCES repos_queue(full_name),
    status TEXT NOT NULL CHECK (status IN ('awaiting_review', 'confirmed_malicious', 'marked_safe')),
    snapshot_path TEXT,
    reviewed_at TEXT
);
"""


class Store:
    """Small SQLite/libSQL-compatible singleton, keyed by database path."""

    _instances: dict[str, Store] = {}

    def __new__(cls, path: str | Path = "data/git_hunter.db") -> Store:
        key = str(Path(path).expanduser().resolve())
        if key not in cls._instances:
            instance = super().__new__(cls)
            instance._database_key = key
            cls._instances[key] = instance
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

    def enqueue(self, full_name: str, html_url: str, priority: int, source: str) -> bool:
        cursor = self.connection.execute(
            "INSERT OR IGNORE INTO repos_queue(full_name, html_url, priority, source) VALUES (?, ?, ?, ?)",
            (full_name, html_url, priority, source),
        )
        self.connection.commit()
        return cursor.rowcount == 1

    def claim_next(self) -> sqlite3.Row | None:
        self.connection.execute("BEGIN IMMEDIATE")
        row = self.connection.execute(
            "SELECT * FROM repos_queue WHERE status='pending' ORDER BY priority DESC, added_at LIMIT 1"
        ).fetchone()
        if row:
            self.connection.execute("UPDATE repos_queue SET status='analyzing' WHERE id=?", (row["id"],))
            row = self.connection.execute("SELECT * FROM repos_queue WHERE id=?", (row["id"],)).fetchone()
        self.connection.commit()
        return row

    def save_result(self, full_name: str, result: dict[str, Any], markdown: str, ai_summary: str | None) -> None:
        self.connection.execute(
            "INSERT INTO scan_results(repo_full_name, anomaly_score, findings_json, markdown, ai_summary) VALUES (?, ?, ?, ?, ?)",
            (full_name, result["anomaly_score"], json.dumps(result), markdown, ai_summary),
        )
        self.connection.execute(
            "INSERT INTO human_review(repo_full_name, status) VALUES (?, 'awaiting_review') ON CONFLICT(repo_full_name) DO UPDATE SET status='awaiting_review', snapshot_path=NULL, reviewed_at=NULL",
            (full_name,),
        )
        self.connection.execute("UPDATE repos_queue SET status='completed' WHERE full_name=?", (full_name,))
        self.connection.commit()

    def fail(self, full_name: str) -> None:
        self.connection.execute("UPDATE repos_queue SET status='failed' WHERE full_name=?", (full_name,))
        self.connection.commit()

    def review(self, full_name: str, status: str, snapshot_path: str | None = None) -> None:
        self.connection.execute(
            "INSERT INTO human_review(repo_full_name, status, snapshot_path, reviewed_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(repo_full_name) DO UPDATE SET status=excluded.status, snapshot_path=excluded.snapshot_path, reviewed_at=CURRENT_TIMESTAMP",
            (full_name, status, snapshot_path),
        )
        self.connection.commit()

    def reports(self) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT q.id, q.full_name, q.html_url, q.status, r.anomaly_score, r.markdown, r.ai_summary, h.status AS review_status, h.snapshot_path FROM repos_queue q JOIN scan_results r ON r.repo_full_name=q.full_name LEFT JOIN human_review h ON h.repo_full_name=q.full_name WHERE r.anomaly_score > 50 AND (h.status IS NULL OR h.status != 'marked_safe') ORDER BY r.anomaly_score DESC"
        ).fetchall()

    def report(self, repo_id: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT q.id, q.full_name, q.html_url, q.status, r.anomaly_score, r.markdown, r.ai_summary, h.status AS review_status, h.snapshot_path FROM repos_queue q JOIN scan_results r ON r.repo_full_name=q.full_name LEFT JOIN human_review h ON h.repo_full_name=q.full_name WHERE q.id=?",
            (repo_id,),
        ).fetchone()

    def queue_item(self, repo_id: int) -> sqlite3.Row | None:
        return self.connection.execute("SELECT * FROM repos_queue WHERE id=?", (repo_id,)).fetchone()
