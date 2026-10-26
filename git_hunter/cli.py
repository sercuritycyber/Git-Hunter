from __future__ import annotations

import argparse
import json
import logging
import os
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .discovery import GitHubClient, discover, run_wanderer
from .dashboard import DASHBOARD_HTML
from .snapshotter import snapshot_repository
from .storage import Store
from .worker import run_worker


LOGGER = logging.getLogger(__name__)
MAX_REQUEST_BODY_BYTES = 64 * 1024


class RuntimeState:
    def __init__(self) -> None:
        self.config: dict[str, object] = {
            "scan_interval_seconds": 5760.0,
            "target_extensions": [".py", ".sh", ".bash", ".js", ".json"],
            "seed_query": "random",
            "max_repositories_per_cycle": 10,
        }
        self.lock = threading.RLock()
        self.spider_running = False
        self.worker_running = False
        self.spider_event = threading.Event()
        self.worker_event = threading.Event()
        self.current: dict[str, object] = {}
        self.activity: deque[dict[str, str]] = deque(maxlen=80)

    def start(self) -> None:
        with self.lock:
            self.spider_event.set()
            self.worker_event.set()
            self.spider_running = True
            self.worker_running = True
            self.add_activity("System started")

    def stop(self) -> None:
        with self.lock:
            self.spider_event.clear()
            self.worker_event.clear()
            self.spider_running = False
            self.worker_running = False
            self.add_activity("System stopped")

    def update_progress(self, progress: dict[str, object]) -> None:
        with self.lock:
            self.current = {**self.current, **progress, "updated_at": time.time()}
            message = progress.get("message")
            if message:
                self.add_activity(f"{progress.get('full_name', 'Worker')}: {message}")

    def add_activity(self, message: str) -> None:
        self.activity.appendleft({
            "message": message,
            "time": time.strftime("%H:%M:%S"),
        })

    def snapshot(self) -> dict[str, object]:
        with self.lock:
            return {
                "config": dict(self.config),
                "spider_running": self.spider_running,
                "worker_running": self.worker_running,
                "current": dict(self.current),
                "activity": list(self.activity),
            }

    def update_config(self, values: dict[str, object]) -> None:
        with self.lock:
            self.config.update(values)
            self.add_activity("Runtime configuration updated")


class Dashboard(BaseHTTPRequestHandler):
    store: Store
    state = RuntimeState()
    github_client = None

    def _send_json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _read_json_body(self) -> object | None:
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or "0")
        except ValueError:
            self.send_error(400, "invalid Content-Length")
            return None
        if length < 0 or length > MAX_REQUEST_BODY_BYTES:
            self.send_error(413, "request body is too large")
            return None
        try:
            body = self.rfile.read(length)
            return json.loads(body or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "invalid JSON")
            return None

    def _database_unavailable(self, error: Exception) -> None:
        LOGGER.error("[-] Database request failed: %s", type(error).__name__)
        self.send_error(503, "database unavailable; check database settings")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/reports":
            try:
                reports = self.store.reports()
            except Exception as error:
                self._database_unavailable(error)
                return
            self._send_json([dict(row) for row in reports])
            return
        if path.startswith("/api/reports/"):
            try:
                report = self.store.report(int(path.rsplit("/", 1)[1]))
            except ValueError:
                report = None
            except Exception as error:
                self._database_unavailable(error)
                return
            if not report:
                self.send_error(404)
                return
            self._send_json(dict(report))
            return
        if path == "/api/config":
            self._send_json(self.state.snapshot()["config"])
            return
        if path == "/api/db/inspect":
            query = parse_qs(urlparse(self.path).query)
            status = query.get("status", ["failed"])[0]
            try:
                rows = self.store.query_status(status, limit=50)
            except ValueError:
                self.send_error(400, "unsupported queue status")
                return
            except Exception as error:
                self._database_unavailable(error)
                return
            self._send_json(rows)
            return
        if path == "/api/system/status":
            try:
                started = time.monotonic()
                self.store.client.execute("SELECT 1")
                snapshot = self.state.snapshot()
                queue = self.store.queue_stats()
            except Exception as error:
                self._database_unavailable(error)
                return
            self._send_json({
                "worker_state": "running" if snapshot["worker_running"] else "stopped",
                "spider_state": "running" if snapshot["spider_running"] else "stopped",
                "turso_latency_ms": round((time.monotonic() - started) * 1000, 2),
                "github_rate_limit_remaining": (
                    self.github_client.rate_limit_remaining if self.github_client else None
                ),
                "github_token_configured": bool(self.github_client and self.github_client.token),
                "github_auth_failed": bool(self.github_client and getattr(self.github_client, "auth_failed", False)),
                "setup_required": not bool(self.github_client and self.github_client.token),
                "database_url": self.store.database_url,
                "queue": queue,
                "last_event": snapshot["activity"][0]["message"] if snapshot["activity"] else None,
            })
            return
        if path == "/api/system/current":
            self._send_json(self.state.snapshot()["current"])
            return
        if path == "/api/activity":
            self._send_json(self.state.snapshot()["activity"])
            return
        if path == "/api/setup":
            self._send_json({
                "github_token_configured": bool(self.github_client and self.github_client.token),
                "github_auth_failed": bool(self.github_client and getattr(self.github_client, "auth_failed", False)),
                "turso_database_url": self.store.database_url,
                "turso_auth_token_configured": self.store.auth_token_configured,
            })
            return
        if path == "/":
            self._send_html(DASHBOARD_HTML)
            return

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path in {"/api/config", "/api/setup", "/api/system/start", "/api/system/stop"}:
            payload = self._read_json_body()
            if payload is None:
                return
            if path == "/api/config":
                if not isinstance(payload, dict):
                    self.send_error(400, "config must be an object")
                    return
                if "scan_interval_seconds" in payload:
                    try:
                        interval = float(payload["scan_interval_seconds"])
                    except (TypeError, ValueError):
                        self.send_error(400, "scan_interval_seconds must be a positive number")
                        return
                    if interval <= 0:
                        self.send_error(400, "scan_interval_seconds must be a positive number")
                        return
                    payload["scan_interval_seconds"] = interval
                if "target_extensions" in payload:
                    extensions = payload["target_extensions"]
                    if (
                        not isinstance(extensions, list)
                        or not extensions
                        or not all(isinstance(extension, str) and extension.startswith(".") for extension in extensions)
                    ):
                        self.send_error(400, "target_extensions must be a non-empty list of extensions")
                        return
                    payload["target_extensions"] = extensions
                if "seed_query" in payload and (
                    not isinstance(payload["seed_query"], str) or not payload["seed_query"].strip()
                ):
                    self.send_error(400, "seed_query must be a non-empty string")
                    return
                if "max_repositories_per_cycle" in payload:
                    try:
                        max_repositories = int(payload["max_repositories_per_cycle"])
                    except (TypeError, ValueError):
                        self.send_error(400, "max_repositories_per_cycle must be a positive integer")
                        return
                    if not 1 <= max_repositories <= 100:
                        self.send_error(400, "max_repositories_per_cycle must be between 1 and 100")
                        return
                    payload["max_repositories_per_cycle"] = max_repositories
                self.state.update_config({
                    key: payload[key] for key in self.state.snapshot()["config"] if key in payload
                })
                self._send_json(self.state.snapshot()["config"])
                return
            if path == "/api/setup":
                if not isinstance(payload, dict):
                    self.send_error(400, "setup must be an object")
                    return
                if "github_token" in payload:
                    token = payload["github_token"]
                    if not isinstance(token, str) or not token.strip():
                        self.send_error(400, "github_token must be a non-empty string")
                        return
                    if self.github_client:
                        self.github_client.token = token.strip()
                        self.github_client.auth_failed = False
                    self.state.add_activity("GitHub token updated")
                database_url = payload.get("turso_database_url")
                database_token = payload.get("turso_auth_token")
                if database_url is not None or database_token is not None:
                    if database_url is None:
                        database_url = self.store.database_url
                    if isinstance(database_url, str):
                        database_url = database_url.strip()
                    if not isinstance(database_url, str) or not database_url.startswith(("libsql://", "https://", "file:")):
                        self.send_error(400, "turso_database_url must be a Turso libsql/https or file URL")
                        return
                    if database_token is not None and (
                        not isinstance(database_token, str) or not database_token.strip()
                    ):
                        self.send_error(400, "turso_auth_token must be a non-empty string")
                        return
                    self.state.stop()
                    try:
                        self.store.reconfigure(database_url, database_token.strip() if database_token else None)
                    except (RuntimeError, ValueError) as error:
                        LOGGER.exception("[-] Could not configure database")
                        self.send_error(502, f"database connection failed: {error}")
                        return
                    self.state.add_activity("Database connection updated; system is stopped")
                elif "turso_database_url" in payload:
                    url = payload["turso_database_url"]
                    if not isinstance(url, str):
                        self.send_error(400, "turso_database_url must be a string")
                        return
                self._send_json({
                    "github_token_configured": bool(self.github_client and self.github_client.token),
                    "turso_auth_token_configured": self.store.auth_token_configured,
                    "system_stopped": not self.state.snapshot()["spider_running"],
                })
                return
            if payload:
                self.send_error(400, "system control endpoints do not accept a body")
                return
            if path.endswith("/start"):
                if not self.github_client or not self.github_client.token:
                    self.send_error(409, "enter a GitHub token in Settings before starting the system")
                    return
                self.state.start()
            else:
                self.state.stop()
            self._send_json({
                "worker_state": "running" if self.state.worker_running else "stopped",
                "spider_state": "running" if self.state.spider_running else "stopped",
            })
            return
        if not path.startswith("/api/review/"):
            self.send_error(404)
            return
        try:
            repo_id = int(path.rsplit("/", 1)[1])
        except ValueError:
            self.send_error(400, "invalid review request")
            return
        body = self._read_json_body()
        if not isinstance(body, dict):
            self.send_error(400, "invalid review request")
            return
        decision = body.get("decision", body.get("status"))
        if decision not in {"malicious_confirmed", "safe"}:
            self.send_error(400, "decision must be malicious_confirmed or safe")
            return
        try:
            row = self.store.queue_item(repo_id)
        except Exception as error:
            self._database_unavailable(error)
            return
        if not row:
            self.send_error(404)
            return
        snapshot_path = None
        if decision == "malicious_confirmed":
            try:
                snapshot_path = snapshot_repository(
                    row["full_name"],
                    token=self.github_client.token if self.github_client else None,
                )
            except Exception as error:
                LOGGER.exception("[-] Could not quarantine %s", row["full_name"])
                self.send_error(502, str(error))
                return
        try:
            self.store.review(repo_id, decision)
        except Exception as error:
            self._database_unavailable(error)
            return
        self._send_json({"decision": decision, "snapshot_path": snapshot_path}, 200)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(prog="git-hunter")
    parser.add_argument("--db", default="data/git_hunter.db")
    sub = parser.add_subparsers(dest="command")
    found = sub.add_parser("discover")
    found.add_argument("--query", required=True)
    found.add_argument("--limit", type=int, default=10)
    worker = sub.add_parser("worker")
    worker.add_argument("--once", action="store_true")
    dashboard = sub.add_parser("dashboard")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    store = Store(args.db)
    if args.command is None:
        args.command = "dashboard"
        args.port = 8080
    if args.command == "discover":
        print(f"Queued {discover(store, args.query, args.limit)} repositories")
    elif args.command == "worker":
        run_worker(store, once=args.once)
    else:
        Dashboard.store = store
        client = GitHubClient()
        Dashboard.github_client = client
        Dashboard.state.stop()
        shutdown_event = threading.Event()
        server = ThreadingHTTPServer((args.host, args.port), Dashboard)
        spider_thread = threading.Thread(
            target=run_wanderer,
            args=(store, Dashboard.state.spider_event),
            kwargs={
                "client": client,
                "seed_query": lambda: str(Dashboard.state.snapshot()["config"]["seed_query"]),
                "limit": lambda: int(Dashboard.state.snapshot()["config"]["max_repositories_per_cycle"]),
                "status": Dashboard.state.add_activity,
                "shutdown_event": shutdown_event,
            },
            name="git-hunter-spider",
            daemon=True,
        )
        worker_thread = threading.Thread(
            target=run_worker,
            args=(store,),
            kwargs={
                "client": client,
                "interval_seconds": lambda: float(Dashboard.state.config["scan_interval_seconds"]),
                "run_event": Dashboard.state.worker_event,
                "shutdown_event": shutdown_event,
                "progress": Dashboard.state.update_progress,
                "extensions": lambda: tuple(Dashboard.state.snapshot()["config"]["target_extensions"]),
            },
            name="git-hunter-worker",
            daemon=True,
        )
        web_thread = threading.Thread(
            target=server.serve_forever,
            name="git-hunter-web",
            daemon=True,
        )
        spider_thread.start()
        worker_thread.start()
        web_thread.start()
        try:
            web_thread.join()
        except KeyboardInterrupt:
            pass
        finally:
            Dashboard.state.stop()
            shutdown_event.set()
            server.shutdown()
            spider_thread.join(timeout=5)
            worker_thread.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    main()
