from __future__ import annotations

import subprocess
import logging


LOGGER = logging.getLogger(__name__)


def enrich(trace: str, timeout: int = 5) -> str | None:
    try:
        completed = subprocess.run(
            ["claude", "-p", "Analyze this execution path. Summarize likely intent. Keep it under 3 sentences."],
            input=trace,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        LOGGER.warning("[*] Claude enrichment unavailable; continuing without AI summary")
        return None
    if completed.returncode != 0:
        LOGGER.warning("[*] Claude exited with status %s; continuing without AI summary", completed.returncode)
        return None
    return completed.stdout.strip() or None