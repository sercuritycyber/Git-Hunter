from __future__ import annotations

import argparse
import json
import os
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .analyzer import analyze_python_sources, markdown_report
from .discovery import GitHubClient, discover
from .enrichment import enrich
from .storage import Store


def _snapshot(url: str, directory: str) -> None:
    request = urllib.request.Request(url.replace("github.com/", "api.github.com/repos/") + "/zipball")
    if os.getenv("GITHUB_TOKEN"):
        request.add_header("Authorization", f"Bearer {os.environ['GITHUB_TOKEN']}")
    with urllib.request.urlopen(request, timeout=30) as response, zipfile.ZipFile(response) as archive:
        archive.extractall(directory)


def run_worker(store: Store, once: bool) -> None:
    client = GitHubClient()
    while True:
        row = store.claim_next()
        if not row:
            return
        try:
            if not row["full_name"]:
                raise ValueError("Queued repository is missing full_name")
            result = analyze_python_sources(client.python_sources(row["full_name"]))
            ai_analysis = enrich(json.dumps(result))
            report = markdown_report(row["full_name"], result, ai_analysis)
            Path("reports").mkdir(exist_ok=True)
            Path("reports", f"{row['id']}.md").write_text(report, encoding="utf-8")
            store.save_result(row["id"], result, report, ai_analysis)
        except Exception:
            store.fail(row["id"])
        if once:
            return


class Dashboard(BaseHTTPRequestHandler):
    store = Store()
    client = GitHubClient()

    def do_GET(self) -> None:
        if self.path == "/api/reports":
            payload = [dict(row) for row in self.store.reports()]
            body = json.dumps(payload).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body); return
            body = b"""<html><body><h1>Git-Hunter review queue</h1><div id='reports'></div>
<script>
async function load() {
    const reports = await (await fetch('/api/reports')).json();
    document.getElementById('reports').innerHTML = reports.map(r =>
        `<article><h2>${r.full_name || r.url}</h2><p>Score: ${r.anomaly_score ?? 'pending'}</p>
        <button onclick="review(${r.id}, 'malicious')">Confirm Malicious</button>
        <button onclick="review(${r.id}, 'safe')">Mark Safe</button></article>`).join('');
}
async function review(id, decision) {
    await fetch(`/api/review/${id}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({decision})});
    load();
}
load();
</script></body></html>"""
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(body)

    def do_POST(self) -> None:
        parts = self.path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "review":
            length = int(self.headers.get("Content-Length", 0)); decision = json.loads(self.rfile.read(length))["decision"]
            repo_id = int(parts[2])
            if decision not in {"malicious", "safe"}:
                self.send_error(400, "decision must be malicious or safe")
                return
            row = self.store.queue_item(repo_id)
            if not row:
                self.send_error(404)
                return
            self.store.review(repo_id, decision)
            if decision == "malicious":
                try:
                    name = (row["full_name"] or f"repo-{repo_id}").replace("/", "_")
                    target = Path(os.getenv("COLD_STORAGE_PATH", "cold_storage")) / f"{repo_id}-{name}"
                    target.mkdir(parents=True, exist_ok=True)
                    _snapshot(row["url"], str(target))
                except Exception as error:
                    self.send_error(502, f"snapshot failed: {error}")
                    return
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
    else:
        Dashboard.store = store
        ThreadingHTTPServer(("127.0.0.1", args.port), Dashboard).serve_forever()


if __name__ == "__main__":
    main()