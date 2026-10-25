from __future__ import annotations

import subprocess


def enrich(trace: str, timeout: int = 5) -> str | None:
    try:
        completed = subprocess.run(
            ["claude", "-p", "Analyze this execution path. Summarize likely intent in under 3 sentences."],
            input=trace,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip() or None