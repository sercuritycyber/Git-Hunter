from __future__ import annotations

import argparse
import json
import os
import tempfile
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .analyzer import analyze_python_files, markdown_report
from .discovery import discover
from .enrichment import enrich
from .storage import Store


def _snapshot(url: str, directory: str) -> None:
    request = urllib.request.Request(url.replace("github.com/", "api.github.com/repos/") + "/zipball")
    if os.getenv("GITHUB_TOKEN"):
        request.add_header("Authorization", f"Bearer {os.environ['GITHUB_TOKEN']}")
    with urllib.request.urlopen(request, timeout=30) as response, zipfile.ZipFile(response) as archive:
        archive.extractall(directory)


def run_worker(store: Store, once: bool) -> None:
    while True:
        row = store.claim_next()
        if not row:
            return
        with tempfile.TemporaryDirectory() as directory:
            try:
                _snapshot(row["url"], directory)
                result = analyze_python_files(directory)
                ai_analysis = enrich(json.dumps(result))
                report = markdown_report(row["full_name"] or row["url"], result, ai_analysis)
                Path("reports").mkdir(exist_ok=True)
                Path("reports", f"{row['id']}.md").write_text(report, encoding="utf-8")
                store.save_result(row["id"], result, report, ai_analysis)
            except Exception:
                store.fail(row["id"])
        if once:
            return


class Dashboard(BaseHTTPRequestHandler):
    store = Store()

    def do_GET(self) -> None:
        if self.path == "/api/reports":
            payload = [dict(row) for row in self.store.reports()]
            body = json.dumps(payload).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body); return
        body = b"<html><body><h1>Git-Hunter review queue</h1><p>Reports: <a href='/api/reports'>/api/reports</a></p></body></html>"
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(body)

    def do_POST(self) -> None:
        parts = self.path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "review":
            length = int(self.headers.get("Content-Length", 0)); decision = json.loads(self.rfile.read(length))["decision"]
            self.store.review(int(parts[2]), decision)
            self.send_response(204); self.end_headers(); return
        self.send_error(404)


def main() -> None:
    parser = argparse.ArgumentParser(prog="git-hunter")
    parser.add_argument("--db", default="data/git_hunter.db")
    sub = parser.add_subparsers(dest="command", required=True)
    found = sub.add_parser("discover"); found.add_argument("--query", required=True); found.add_argument("--limit", type=int, default=10)
    worker = sub.add_parser("worker"); worker.add_argument("--once", action="store_true")
    dashboard = sub.add_parser("dashboard"); dashboard.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(); store = Store(args.db)
    if args.command == "discover": print(f"Queued {discover(store, args.query, args.limit)} repositories")
    elif args.command == "worker": run_worker(store, args.once)
    else: ThreadingHTTPServer(("127.0.0.1", args.port), Dashboard).serve_forever()


if __name__ == "__main__":
    main()