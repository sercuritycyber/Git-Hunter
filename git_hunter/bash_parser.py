from __future__ import annotations

import logging
import math
import re
from pathlib import Path
from typing import Any

from .signatures import scan_source

LOGGER = logging.getLogger(__name__)
BLOB_PATTERN = re.compile(r"^[A-Za-z0-9+/=]{80,}$|^[0-9a-fA-F]{80,}$")
ASSIGNMENT_PATTERN = re.compile(
    r"^\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:['\"])?(?P<value>[A-Za-z0-9+/=]{80,}|[0-9a-fA-F]{80,})(?:['\"])?\s*(?:#.*)?$"
)
SINK_PATTERN = re.compile(r"\b(?P<sink>eval|bash\s+-c|sh\s+-c)\b(?P<arguments>.*)")
VARIABLE_PATTERN = re.compile(r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _blob_metadata(value: str, line: int) -> dict[str, Any] | None:
    candidate = value.strip().strip("'\"")
    if not BLOB_PATTERN.fullmatch(candidate):
        return None
    entropy = _entropy(candidate)
    if entropy <= 5.5:
        return None
    return {"line": line, "entropy": entropy}


class BashAnalyzer:
    """Heuristic shell analyzer for high-entropy blobs reaching execution sinks."""

    def __init__(self, source: str, filename: str = "<memory>") -> None:
        self.source = source
        self.filename = filename
        self.tracked_vars: dict[str, dict[str, Any]] = {}
        self.findings: list[dict[str, Any]] = []

    def _track_assignment(self, line: str, line_number: int) -> None:
        match = ASSIGNMENT_PATTERN.match(line)
        if not match:
            return
        metadata = _blob_metadata(match.group("value"), line_number)
        if metadata:
            self.tracked_vars[match.group("name")] = metadata

    def _inspect_sink(self, line: str, line_number: int) -> None:
        match = SINK_PATTERN.search(line)
        if not match:
            return
        sink = re.sub(r"\s+", " ", match.group("sink"))
        arguments = match.group("arguments")
        variables = [item.group("braced") or item.group("plain") for item in VARIABLE_PATTERN.finditer(arguments)]
        traced_variable = next((name for name in variables if name in self.tracked_vars), None)
        if traced_variable:
            metadata = self.tracked_vars[traced_variable]
            self.findings.append({
                "line": line_number,
                "sink": sink,
                "kind": "traced_execution_sink",
                "source_var": traced_variable,
                "source_line": metadata["line"],
                "entropy": metadata["entropy"],
            })
            return
        direct_blob = next((token.strip("'\"") for token in arguments.split() if BLOB_PATTERN.fullmatch(token.strip("'\""))), None)
        if direct_blob:
            self.findings.append({
                "line": line_number,
                "sink": sink,
                "kind": "direct_execution_sink",
                "source_line": line_number,
                "entropy": _entropy(direct_blob),
            })
            return
        # A shell execution primitive is not malicious by itself. Without a
        # high-entropy payload reaching it, there is no behavioral finding.

    def analyze(self) -> dict[str, Any]:
        for line_number, line in enumerate(self.source.splitlines(), start=1):
            self._track_assignment(line, line_number)
            self._inspect_sink(line, line_number)
        weights = {"traced_execution_sink": 75, "direct_execution_sink": 50, "execution_or_network": 15}
        behavioral_findings = [{"file": self.filename, **item} for item in self.findings]
        static_findings = [{"file": self.filename, **item} for item in scan_source(self.source)]
        findings = behavioral_findings + static_findings
        score = min(100, sum(
            finding.get("weight", weights.get(finding["kind"], 0))
            for finding in findings
        ))
        return {"anomaly_score": score, "findings": findings, "files_scanned": 1}


def analyze_bash_sources(sources: dict[str, str]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    total_score = 0
    for filename, source in sources.items():
        result = BashAnalyzer(source, filename).analyze()
        findings.extend(result["findings"])
        total_score += result["anomaly_score"]
    return {"anomaly_score": min(100, total_score), "findings": findings, "files_scanned": len(sources)}


def analyze_bash_files(root: str | Path) -> dict[str, Any]:
    sources: dict[str, str] = {}
    for path in Path(root).rglob("*"):
        if path.suffix not in {".sh", ".bash"}:
            continue
        try:
            sources[str(path.relative_to(root))] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            LOGGER.error("[-] Could not read %s: %s", path, error)
    return analyze_bash_sources(sources)
