from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable

from .analyzer import analyze_python_sources, markdown_report
from .bash_parser import analyze_bash_sources
from .discovery import GitHubClient
from .enrichment import enrich
from .js_parser import analyze_js_sources
from .storage import Store


LOGGER = logging.getLogger(__name__)
DAILY_SCAN_INTERVAL = 24 * 60 * 60 / 15


def analyze_repository_sources(sources: dict[str, str]) -> dict[str, object]:
    python_sources = {path: source for path, source in sources.items() if path.endswith(".py")}
    bash_sources = {path: source for path, source in sources.items() if path.endswith((".sh", ".bash"))}
    javascript_sources = {path: source for path, source in sources.items() if path.endswith((".js", ".json"))}
    results = [
        analyze_python_sources(python_sources),
        analyze_bash_sources(bash_sources),
        analyze_js_sources(javascript_sources),
    ]
    findings = [finding for result in results for finding in result["findings"]]
    return {
        "anomaly_score": min(100, sum(int(result["anomaly_score"]) for result in results)),
        "findings": findings,
        "files_scanned": sum(int(result["files_scanned"]) for result in results),
    }


def process_next(store: Store, client: GitHubClient | None = None) -> bool:
    client = client or GitHubClient()
    row = store.claim_next()
    if not row:
        return False
    full_name = row["full_name"]
    try:
        sources = client.repository_sources(full_name)
        result = analyze_repository_sources(sources)
        ai_summary = enrich(json.dumps(result), timeout=5.0)
        result["ai_summary"] = ai_summary
        report = markdown_report(full_name, result, ai_summary)
        store.save_result(row["id"], result, report)
        LOGGER.info("[+] Completed %s with score %s", full_name, result["anomaly_score"])
    except Exception:
        LOGGER.exception("[-] Scan failed for %s", full_name)
        store.fail(row["id"])
    return True


def run_worker(
    store: Store,
    once: bool = False,
    interval_seconds: float | Callable[[], float] = DAILY_SCAN_INTERVAL,
    client: GitHubClient | None = None,
    run_event: object | None = None,
) -> None:
    while run_event is None or run_event.is_set():
        processed = process_next(store, client)
        if once:
            return
        wait_seconds = interval_seconds() if callable(interval_seconds) else interval_seconds
        LOGGER.info("[*] Waiting %.0f seconds before the next scan", wait_seconds)
        if run_event is not None and hasattr(run_event, "wait"):
            run_event.wait(wait_seconds)
        else:
            time.sleep(wait_seconds)
        if not processed and run_event is None:
            return
