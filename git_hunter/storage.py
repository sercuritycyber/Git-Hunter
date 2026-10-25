from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS repos_queue (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    full_name TEXT,
    priority REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    claimed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY,
    repo_id INTEGER NOT NULL REFERENCES repos_queue(id),
    anomaly_score REAL NOT NULL,
    result_json TEXT NOT NULL,
    markdown TEXT NOT NULL,
    ai_analysis TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS human_review (
    repo_id INTEGER PRIMARY KEY REFERENCES repos_queue(id),
    decision TEXT NOT NULL CHECK (decision IN ('malicious', 'safe')),
    reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


class Store:
    def __init__(self, path: str | Path = "data/git_hunter.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def enqueue(self, url: str, full_name: str | None = None, priority: float = 0) -> bool:
        cursor = self.connection.execute(
            "INSERT OR IGNORE INTO repos_queue(url, full_name, priority) VALUES (?, ?, ?)",
            (url, full_name, priority),
        )
        self.connection.commit()
        return cursor.rowcount == 1

    def claim_next(self) -> sqlite3.Row | None:
        self.connection.execute("BEGIN IMMEDIATE")
        row = self.connection.execute(
            "SELECT * FROM repos_queue WHERE status = 'pending' ORDER BY priority DESC, created_at LIMIT 1"
        ).fetchone()
        if row:
            self.connection.execute(
                "UPDATE repos_queue SET status='scanning', attempts=attempts+1, claimed_at=CURRENT_TIMESTAMP WHERE id=?",
                (row["id"],),
            )
        self.connection.commit()
        return row

    def save_result(self, repo_id: int, result: dict[str, Any], markdown: str, ai_analysis: str | None) -> None:
        self.connection.execute(
            "INSERT INTO scan_results(repo_id, anomaly_score, result_json, markdown, ai_analysis) VALUES (?, ?, ?, ?, ?)",
            (repo_id, result["anomaly_score"], json.dumps(result), markdown, ai_analysis),
        )
        self.connection.execute("UPDATE repos_queue SET status='complete' WHERE id=?", (repo_id,))
        self.connection.commit()

    def fail(self, repo_id: int) -> None:
        self.connection.execute("UPDATE repos_queue SET status='failed' WHERE id=?", (repo_id,))
        self.connection.commit()

    def review(self, repo_id: int, decision: str) -> None:
        self.connection.execute(
            "INSERT INTO human_review(repo_id, decision) VALUES (?, ?) ON CONFLICT(repo_id) DO UPDATE SET decision=excluded.decision, reviewed_at=CURRENT_TIMESTAMP",
            (repo_id, decision),
        )
        self.connection.commit()

    def reports(self) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT q.id, q.full_name, q.url, q.status, r.anomaly_score, r.markdown, h.decision FROM repos_queue q LEFT JOIN scan_results r ON r.repo_id=q.id LEFT JOIN human_review h ON h.repo_id=q.id ORDER BY r.anomaly_score DESC"
        ).fetchall()