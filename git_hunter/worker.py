from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import Any

from .analyzer import analyze_python_sources, markdown_report
from .bash_parser import analyze_bash_sources
from .discovery import GitHubAuthenticationError, GitHubClient
from .enrichment import enrich
from .js_parser import analyze_js_sources
from .storage import Store


LOGGER = logging.getLogger(__name__)
DAILY_SCAN_INTERVAL = 24 * 60 * 60 / 15


def _wait_for_control(
    run_event: object | None,
    shutdown_event: object | None,
    seconds: float,
) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if shutdown_event is not None and shutdown_event.is_set():
            return
        if run_event is not None and not run_event.is_set():
            return
        time.sleep(min(0.25, deadline - time.monotonic()))


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


def process_next(
    store: Store,
    client: GitHubClient | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
    extensions: Callable[[], tuple[str, ...]] | None = None,
) -> bool:
    client = client or GitHubClient()
    if getattr(client, "auth_failed", False):
        return False
    row = store.claim_next()
    if not row:
        return False
    full_name = row["full_name"]
    stage = "claim"
    def update(**values: Any) -> None:
        if progress:
            progress({"repo_id": row["id"], "full_name": full_name, **values})

    try:
        stage = "fetching"
        update(stage="fetching", message="Fetching repository tree", files_scanned=0)
        source_extensions = extensions() if extensions else (".py", ".sh", ".bash", ".js", ".json")
        sources = client.repository_sources(full_name, source_extensions)
        stage = "analyzing"
        update(
            stage="analyzing",
            message="Analyzing repository sources",
            files_scanned=len(sources),
            source_paths=sorted(sources),
            source_preview=next(iter(sources.values()), "")[:4000],
        )
        result = analyze_repository_sources(sources)
        stage = "enriching"
        update(
            stage="enriching",
            message="Preparing findings and summary",
            files_scanned=len(sources),
            anomaly_score=result["anomaly_score"],
        )
        ai_summary = enrich(json.dumps(result), timeout=5.0)
        result["ai_summary"] = ai_summary
        report = markdown_report(full_name, result, ai_summary)
        store.save_result(row["id"], result, report)
        update(stage="completed", message="Analysis complete", anomaly_score=result["anomaly_score"])
        LOGGER.info("[+] Completed %s with score %s", full_name, result["anomaly_score"])
    except GitHubAuthenticationError as error:
        update(stage="failed", message=str(error))
        LOGGER.error("[-] Scan paused: %s", error)
        try:
            store.fail(row["id"], stage=stage, reason="github_authentication")
        except Exception:
            LOGGER.exception("[-] Could not mark %s as failed", full_name)
    except Exception as error:
        update(stage="failed", message="Analysis failed")
        LOGGER.exception("[-] Scan failed for %s", full_name)
        try:
            store.fail(row["id"], stage=stage, reason=type(error).__name__)
        except Exception:
            LOGGER.exception("[-] Could not mark %s as failed", full_name)
    return True


def run_worker(
    store: Store,
    once: bool = False,
    interval_seconds: float | Callable[[], float] = DAILY_SCAN_INTERVAL,
    client: GitHubClient | None = None,
    run_event: object | None = None,
    shutdown_event: object | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
    extensions: Callable[[], tuple[str, ...]] | None = None,
) -> None:
    while shutdown_event is None or not shutdown_event.is_set():
        if run_event is not None and not run_event.is_set():
            if hasattr(run_event, "wait"):
                run_event.wait(0.25)
            else:
                time.sleep(0.25)
            continue
        processed = process_next(store, client, progress, extensions)
        if client is not None and getattr(client, "auth_failed", False):
            if run_event is not None and hasattr(run_event, "clear"):
                run_event.clear()
            if once:
                return
            _wait_for_control(run_event, shutdown_event, 1.0)
            continue
        if once:
            return
        wait_seconds = 1.0 if processed else 5.0
        _wait_for_control(run_event, shutdown_event, wait_seconds)
