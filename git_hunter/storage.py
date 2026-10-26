from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import libsql_client

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS queue (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'scanning', 'completed', 'failed', 'malicious_confirmed', 'safe')),
    priority INTEGER NOT NULL DEFAULT 0
    ,failure_stage TEXT
    ,failure_reason TEXT
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
        url = os.getenv("TURSO_DATABASE_URL", "").strip() or f"file:{self.path.resolve()}"
        token = os.getenv("TURSO_AUTH_TOKEN")
        self._prepare_local_database(url)
        self.database_url = url
        self._auth_token = token
        self.auth_token_configured = bool(token)
        self._claim_lock = threading.Lock()
        self._schema_lock = threading.Lock()
        try:
            self.client = self._create_client(url, token)
        except Exception as error:
            raise RuntimeError(self._connection_error(url, error)) from error
        self._initialize_client()
        self._initialized = True

    @staticmethod
    def _local_path(url: str) -> Path | None:
        parsed = urlparse(url)
        if parsed.scheme != "file":
            return None
        return Path(unquote(parsed.path)).expanduser()

    def _prepare_local_database(self, url: str) -> None:
        local_path = self._local_path(url)
        if local_path is None:
            return
        try:
            local_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise RuntimeError(
                f"Cannot create local database directory '{local_path.parent}': {error}. "
                "Choose a writable --db path or configure Turso in the dashboard."
            ) from error

    @staticmethod
    def _connection_error(url: str, error: Exception) -> str:
        parsed = urlparse(url)
        if parsed.scheme == "file":
            location = unquote(parsed.path)
            return (
                f"Cannot open local database '{location}': {error}. "
                "Check that the path is writable and its parent directory exists."
            )
        return (
            f"Cannot connect to database '{parsed.scheme}://{parsed.netloc}': {error}. "
            "Check the Turso URL and enter a valid auth token in the dashboard."
        )

    def _create_client(self, url: str, token: str | None) -> Any:
        return libsql_client.create_client_sync(url, auth_token=token)

    def _initialize_client(self) -> None:
        with self._schema_lock:
            marker = self._one(self.client.execute(
                "SELECT value FROM schema_metadata WHERE key = ?",
                ("schema_version",),
            )) if self._table_exists("schema_metadata") else None
            if marker is None:
                execute_batch = getattr(self.client, "execute_batch", None)
                if execute_batch:
                    execute_batch(SCHEMA)
                else:
                    statements = [statement.strip() for statement in SCHEMA.split(";") if statement.strip()]
                    self.client.batch(statements)
                self.client.execute(
                    "INSERT OR REPLACE INTO schema_metadata(key, value) VALUES (?, ?)",
                    ("schema_version", "1"),
                )
            self._verify_schema()
        executor = getattr(self.client, "_executor", None)
        thread = getattr(executor, "_thread", None)
        if thread is not None:
            thread._daemonic = True
        register_shutdown = getattr(threading, "_register_atexit", None)
        if register_shutdown is not None:
            register_shutdown(self.client.close)

    def _table_exists(self, name: str) -> bool:
        return self._one(self.client.execute(
            "SELECT name FROM sqlite_master WHERE type = ? AND name = ?",
            ("table", name),
        )) is not None

    def _verify_schema(self) -> None:
        columns = {
            str(row["name"]) for row in self._rows(self.client.execute("PRAGMA table_info(queue)"))
        }
        migrations = {
            "failure_stage": "ALTER TABLE queue ADD COLUMN failure_stage TEXT",
            "failure_reason": "ALTER TABLE queue ADD COLUMN failure_reason TEXT",
        }
        for column, statement in migrations.items():
            if column not in columns:
                self.client.execute(statement)
        required_tables = {"schema_metadata", "queue", "results"}
        missing = sorted(table for table in required_tables if not self._table_exists(table))
        if missing:
            raise RuntimeError(f"Database schema is incomplete; missing tables: {', '.join(missing)}")

    def reconfigure(self, url: str, token: str | None = None) -> None:
        parsed = urlparse(url)
        valid_turso_host = parsed.hostname and (
            parsed.hostname == "turso.io" or parsed.hostname.endswith(".turso.io")
        )
        if parsed.scheme not in {"libsql", "https", "file"} or (
            parsed.scheme in {"libsql", "https"} and not valid_turso_host
        ):
            raise ValueError("database URL must be a Turso libsql/https URL or a local file URL")
        if token is None and url != self.database_url:
            raise ValueError("enter the auth token again when changing the database URL")
        if token is None:
            token = self._auth_token
        self._prepare_local_database(url)
        previous = self.client
        try:
            client = self._create_client(url, token)
        except Exception as error:
            raise RuntimeError(self._connection_error(url, error)) from error
        self.client = client
        self.database_url = url
        self._auth_token = token
        self.auth_token_configured = bool(token)
        try:
            self._initialize_client()
        except Exception:
            self.client = previous
            client.close()
            raise
        previous.close()

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

    def pending_count(self) -> int:
        row = self._one(self.client.execute(
            "SELECT COUNT(*) AS count FROM queue WHERE status='pending'"
        ))
        return int(row["count"]) if row else 0

    def claim_next(self) -> dict[str, Any] | None:
        with self._claim_lock:
            while True:
                transaction = self.client.transaction()
                try:
                    row = self._one(transaction.execute(
                        "SELECT * FROM queue WHERE status='pending' ORDER BY RANDOM() LIMIT 1"
                    ))
                    if not row:
                        transaction.rollback()
                        return None
                    updated = transaction.execute(
                        "UPDATE queue SET status='scanning' WHERE id=? AND status='pending'",
                        (row["id"],),
                    )
                    if updated.rows_affected != 1:
                        transaction.rollback()
                        continue
                    transaction.commit()
                    row["status"] = "scanning"
                    return row
                except Exception:
                    transaction.rollback()
                    raise
                finally:
                    transaction.close()

    def save_result(self, repo_id: int, result: dict[str, Any], markdown_report: str) -> None:
        self.client.execute(
            "INSERT OR REPLACE INTO results(repo_id, anomaly_score, raw_json, markdown_report) VALUES (?, ?, ?, ?)",
            (repo_id, result["anomaly_score"], json.dumps(result), markdown_report),
        )
        self.client.execute("UPDATE queue SET status='completed' WHERE id=?", (repo_id,))

    def fail(self, repo_id: int, stage: str = "unknown", reason: str = "analysis_failed") -> None:
        self.client.execute(
            "UPDATE queue SET status='failed', failure_stage=?, failure_reason=? WHERE id=?",
            (stage[:80], reason[:120], repo_id),
        )

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

    def query_status(self, status: str, limit: int = 50) -> list[dict[str, Any]]:
        allowed_statuses = {
            "pending",
            "scanning",
            "completed",
            "failed",
            "malicious_confirmed",
            "safe",
        }
        if status not in allowed_statuses:
            raise ValueError("unsupported queue status")
        bounded_limit = max(1, min(int(limit), 200))
        return self._rows(self.client.execute(
            "SELECT id, url, full_name, status, priority, failure_stage, failure_reason FROM queue "
            "WHERE status = ? ORDER BY id DESC LIMIT ?",
            (status, bounded_limit),
        ))

    def queue_stats(self) -> dict[str, int]:
        rows = self._rows(self.client.execute("SELECT status, COUNT(*) AS count FROM queue GROUP BY status"))
        stats = {str(row["status"]): int(row["count"]) for row in rows}
        return {
            "pending": stats.get("pending", 0),
            "scanning": stats.get("scanning", 0),
            "completed": stats.get("completed", 0),
            "failed": stats.get("failed", 0),
            "reviewed": stats.get("safe", 0) + stats.get("malicious_confirmed", 0),
            "total": sum(stats.values()),
        }
