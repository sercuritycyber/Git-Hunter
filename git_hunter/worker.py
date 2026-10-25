from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from .analyzer import analyze_python_sources, markdown_report
from .discovery import GitHubClient
from .enrichment import enrich
from .storage import Store


LOGGER = logging.getLogger(__name__)
DAILY_SCAN_INTERVAL = 24 * 60 * 60 / 15


def process_next(store: Store, client: GitHubClient | None = None) -> bool:
    client = client or GitHubClient()
    row = store.claim_next()
    if not row:
        return False
    full_name = row["full_name"]
    try:
        sources = client.python_sources(full_name)
        result = analyze_python_sources(sources)
        ai_summary = enrich(json.dumps(result), timeout=5.0)
        report = markdown_report(full_name, result, ai_summary)
        Path("reports").mkdir(exist_ok=True)
        Path("reports", f"{row['id']}.md").write_text(report, encoding="utf-8")
        store.save_result(full_name, result, report, ai_summary)
        LOGGER.info("[+] Completed %s with score %s", full_name, result["anomaly_score"])
    except Exception:
        LOGGER.exception("[-] Scan failed for %s", full_name)
        store.fail(full_name)
    return True


def run_worker(store: Store, once: bool = False, interval_seconds: float = DAILY_SCAN_INTERVAL, client: GitHubClient | None = None) -> None:
    while process_next(store, client):
        if once:
            return
        LOGGER.info("[*] Waiting %.0f seconds before the next scan", interval_seconds)
        time.sleep(interval_seconds)
