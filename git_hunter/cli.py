from __future__ import annotations

import argparse
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .discovery import discover
from .snapshotter import snapshot_repository
from .storage import Store
from .worker import run_worker


LOGGER = logging.getLogger(__name__)


def _snapshot(full_name: str) -> str:
    """Download a repository only for an explicit malicious review decision."""
    return snapshot_repository(full_name)


class Dashboard(BaseHTTPRequestHandler):
    store = Store()

    def _send_json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/reports":
            self._send_json([dict(row) for row in self.store.reports()])
            return
        if path.startswith("/api/reports/"):
            try:
                report = self.store.report(int(path.rsplit("/", 1)[1]))
            except ValueError:
                report = None
            if not report:
                self.send_error(404)
                return
            self._send_json(dict(report))
            return
        body = b"""<!doctype html><html><body><h1>Git-Hunter review queue</h1>
<p>High-score reports: <a href='/api/reports'>JSON API</a></p><div id='reports'></div>
<script>
async function load() {
  const reports = await (await fetch('/api/reports')).json();
  document.getElementById('reports').innerHTML = reports.map(r =>
    `<article><h2><a href='${r.url}'>${r.full_name}</a></h2><p>Score: ${r.anomaly_score}</p>
    <pre>${r.markdown_report}</pre>
    <button onclick="review(${r.id}, 'safe')">Mark as Safe</button>
    <button onclick="review(${r.id}, 'malicious')">Confirm Malicious &amp; Quarantine</button></article>`).join('');
}
async function review(id, status) {
  await fetch(`/api/review/${id}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({status})});
  load();
}
load();
</script></body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/api/review/"):
            self.send_error(404)
            return
        try:
            repo_id = int(path.rsplit("/", 1)[1])
            length = int(self.headers.get("Content-Length", "0"))
            decision = json.loads(self.rfile.read(length))["decision"]
        except (ValueError, KeyError, json.JSONDecodeError):
            self.send_error(400, "invalid review request")
            return
        if decision not in {"malicious", "safe"}:
            self.send_error(400, "decision must be malicious or safe")
            return
        row = self.store.queue_item(repo_id)
        if not row:
            self.send_error(404)
            return
        snapshot_path = None
        status = "malicious_confirmed" if decision == "malicious" else "safe"
        if decision == "malicious":
            try:
                snapshot_path = _snapshot(row["full_name"])
            except Exception as error:
                LOGGER.exception("[-] Could not quarantine %s", row["full_name"])
                self.send_error(502, str(error))
                return
        self.store.review(repo_id, status)
        self._send_json({"decision": decision, "snapshot_path": snapshot_path}, 200)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(prog="git-hunter")
    parser.add_argument("--db", default="data/git_hunter.db")
    sub = parser.add_subparsers(dest="command", required=True)
    found = sub.add_parser("discover")
    found.add_argument("--query", required=True)
    found.add_argument("--limit", type=int, default=10)
    worker = sub.add_parser("worker")
    worker.add_argument("--once", action="store_true")
    dashboard = sub.add_parser("dashboard")
    dashboard.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    store = Store(args.db)
    if args.command == "discover":
        print(f"Queued {discover(store, args.query, args.limit)} repositories")
    elif args.command == "worker":
        run_worker(store, once=args.once)
    else:
        Dashboard.store = store
        ThreadingHTTPServer(("127.0.0.1", args.port), Dashboard).serve_forever()


if __name__ == "__main__":
    main()
