from __future__ import annotations

import logging
import os
import shutil
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


LOGGER = logging.getLogger(__name__)


def snapshot_repository(full_name: str, cold_storage: str | Path | None = None, branch: str = "HEAD") -> str:
    root = Path(cold_storage or os.getenv("COLD_STORAGE_PATH", "/mnt/quarantine"))
    root.mkdir(parents=True, exist_ok=True)
    safe_name = full_name.replace("/", "_")
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = root / f"{safe_name}_{timestamp}.zip"
    request = urllib.request.Request(f"https://api.github.com/repos/{full_name}/zipball/{branch}")
    request.add_header("Accept", "application/vnd.github+json")
    token = os.getenv("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=30) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)
    LOGGER.info("[+] Snapshot written to %s", destination)
    return str(destination)
