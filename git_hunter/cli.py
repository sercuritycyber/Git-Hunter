from __future__ import annotations

import argparse
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .discovery import GitHubClient, discover, run_wanderer
from .snapshotter import snapshot_repository
from .storage import Store
from .worker import run_worker


LOGGER = logging.getLogger(__name__)


class RuntimeState:
    def __init__(self) -> None:
        self.config: dict[str, object] = {
            "scan_interval_seconds": 5760.0,
            "target_extensions": [".py", ".sh", ".bash", ".js", ".json"],
        }
        self.spider_running = False
        self.worker_running = False
        self.spider_event = threading.Event()
        self.worker_event = threading.Event()

    def start(self) -> None:
        self.spider_event.set()
        self.worker_event.set()
        self.spider_running = True
        self.worker_running = True

    def stop(self) -> None:
        self.spider_event.clear()
        self.worker_event.clear()
        self.spider_running = False
        self.worker_running = False


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
        if path == "/api/config":
            self._send_json(self.state.config)
            return
        if path == "/api/system/status":
            started = time.monotonic()
            self.store.client.execute("SELECT 1")
            self._send_json({
                "worker_state": "running" if self.state.worker_running else "stopped",
                "spider_state": "running" if self.state.spider_running else "stopped",
                "turso_latency_ms": round((time.monotonic() - started) * 1000, 2),
                "github_rate_limit_remaining": (
                    self.github_client.rate_limit_remaining if self.github_client else None
                ),
            })
            return
        body = b"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Git-Hunter C2</title>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
:root{font:15px system-ui,sans-serif;color:#e8eef8;background:#101722}body{margin:0}
header{padding:1.25rem 2rem;background:#172235;border-bottom:1px solid #2e405d}
main{max-width:1100px;margin:auto;padding:1.5rem 2rem}.tabs{display:flex;gap:.5rem;margin-bottom:1.25rem}
button{border:0;border-radius:6px;padding:.6rem .9rem;cursor:pointer;background:#30486b;color:#fff}
button.active{background:#4f8cff}.panel{display:none}.panel.active{display:block}
article,.card{background:#172235;border:1px solid #2e405d;border-radius:8px;padding:1rem;margin:.8rem 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem}
.metric{font-size:1.5rem;font-weight:700}.label{color:#9fb1cc;font-size:.85rem}
.score{display:inline-block;border-radius:999px;padding:.25rem .65rem;background:#a33;color:#fff}
textarea,input{background:#0d1420;color:#fff;border:1px solid #405372;border-radius:4px;padding:.5rem}
label{display:block;margin:.8rem 0}a{color:#84b4ff}
</style></head><body><header><strong>Git-Hunter C2</strong></header><main>
<nav class="tabs"><button class="tab active" data-panel="queue">Review Queue</button>
<button class="tab" data-panel="status">System Status</button><button class="tab" data-panel="settings">Settings</button></nav>
<section id="queue" class="panel active"><div id="reports"></div></section>
<section id="status" class="panel"><div class="grid">
<div class="card"><div class="label">Worker State</div><div class="metric" id="worker-state">-</div></div>
<div class="card"><div class="label">Spider State</div><div class="metric" id="spider-state">-</div></div>
<div class="card"><div class="label">Turso Latency</div><div class="metric"><span id="turso-latency">-</span> ms</div></div>
<div class="card"><div class="label">GitHub API Remaining</div><div class="metric" id="github-rate">-</div></div>
</div><p><button onclick="system('start')">Start System</button>
<button onclick="system('stop')">Stop System</button></p></section>
<section id="settings" class="panel"><div class="card"><form id="settings-form">
<label>Scan interval (seconds)<br><input id="interval" type="number" min="1" step="1"></label>
<label>Target extensions (one per line)<br><textarea id="extensions" rows="5"></textarea></label>
<button>Save Settings</button></form></div></section>
</main><script>
const $=id=>document.getElementById(id);
document.querySelectorAll('.tab').forEach(tab=>tab.onclick=()=>{
 document.querySelectorAll('.tab,.panel').forEach(el=>el.classList.remove('active'));
 tab.classList.add('active');$(tab.dataset.panel).classList.add('active');
});
async function loadReports(){const reports=await (await fetch('/api/reports')).json();
 $('reports').innerHTML=reports.length?reports.map(r=>`<article><h2><a href="${r.url}" target="_blank">${r.full_name}</a>
 <span class="score">${r.anomaly_score}</span></h2><div>${marked.parse(r.markdown_report)}</div>
 <button onclick="review(${r.id},'safe')">Mark Safe</button>
 <button onclick="review(${r.id},'malicious_confirmed')">Confirm Malicious</button></article>`).join('')
 :' <div class="card">No reports awaiting review.</div>'}
async function review(id,status){await fetch('/api/review/'+id,{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({status})});loadReports()}
async function status(){const s=await (await fetch('/api/system/status')).json();
 $('worker-state').textContent=s.worker_state;$('spider-state').textContent=s.spider_state;
 $('turso-latency').textContent=s.turso_latency_ms;$('github-rate').textContent=s.github_rate_limit_remaining??'unknown'}
async function system(action){await fetch('/api/system/'+action,{method:'POST'});status()}
async function loadConfig(){const c=await (await fetch('/api/config')).json();$('interval').value=c.scan_interval_seconds;
 $('extensions').value=c.target_extensions.join('\\n')}
$('settings-form').onsubmit=async e=>{e.preventDefault();await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({scan_interval_seconds:Number($('interval').value),
 target_extensions:$('extensions').value.split('\\n').map(x=>x.trim()).filter(Boolean)})})};
loadReports();loadConfig();status();setInterval(status,3000);setInterval(loadReports,10000);
</script></body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path in {"/api/config", "/api/system/start", "/api/system/stop"}:
            length = int(self.headers.get("Content-Length", "0"))
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self.send_error(400, "invalid JSON")
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
                    self.state.config["scan_interval_seconds"] = interval
                if "target_extensions" in payload:
                    extensions = payload["target_extensions"]
                    if (
                        not isinstance(extensions, list)
                        or not extensions
                        or not all(isinstance(extension, str) and extension.startswith(".") for extension in extensions)
                    ):
                        self.send_error(400, "target_extensions must be a non-empty list of extensions")
                        return
                    self.state.config["target_extensions"] = extensions
                self._send_json(self.state.config)
                return
            if payload:
                self.send_error(400, "system control endpoints do not accept a body")
                return
            if path.endswith("/start"):
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
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            decision = body.get("decision", body.get("status"))
        except (ValueError, KeyError, json.JSONDecodeError):
            self.send_error(400, "invalid review request")
            return
        if decision not in {"malicious_confirmed", "safe"}:
            self.send_error(400, "decision must be malicious_confirmed or safe")
            return
        row = self.store.queue_item(repo_id)
        if not row:
            self.send_error(404)
            return
        snapshot_path = None
        if decision == "malicious_confirmed":
            try:
                snapshot_path = snapshot_repository(row["full_name"])
            except Exception as error:
                LOGGER.exception("[-] Could not quarantine %s", row["full_name"])
                self.send_error(502, str(error))
                return
        self.store.review(repo_id, decision)
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
        client = GitHubClient()
        Dashboard.github_client = client
        Dashboard.state.start()
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Dashboard)
        spider_thread = threading.Thread(
            target=run_wanderer,
            args=(store, Dashboard.state.spider_event),
            kwargs={"client": client},
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
            server.shutdown()
            spider_thread.join(timeout=5)
            worker_thread.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    main()
