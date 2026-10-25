from __future__ import annotations

import logging
import math
import re
from pathlib import Path
from typing import Any


LOGGER = logging.getLogger(__name__)
STRING_PATTERN = re.compile(r"(['\"])(?P<value>[A-Za-z0-9+/=]{80,}|[0-9a-fA-F]{80,})\1")
ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(['\"])(?P<value>[A-Za-z0-9+/=]{80,}|[0-9a-fA-F]{80,})\2"
)
SINK_PATTERNS = {
    "chrome.tabs.executeScript": re.compile(r"\bchrome\.tabs\.executeScript\b"),
    "eval": re.compile(r"\beval\s*\("),
    "WebSocket": re.compile(r"\b(?:new\s+)?WebSocket\s*\("),
}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _blob_metadata(value: str, line: int) -> dict[str, Any] | None:
    if not re.fullmatch(r"[A-Za-z0-9+/=]{80,}|[0-9a-fA-F]{80,}", value):
        return None
    return {"line": line, "entropy": _entropy(value)}


class JSAnalyzer:
    """Regex-based analyzer for JavaScript browser-extension threat indicators."""

    def __init__(self, source: str, filename: str = "<memory>") -> None:
        self.source = source
        self.filename = filename
        self.tracked_vars: dict[str, dict[str, Any]] = {}
        self.findings: list[dict[str, Any]] = []

    def _track_assignments(self, line: str, line_number: int) -> None:
        for match in ASSIGNMENT_PATTERN.finditer(line):
            metadata = _blob_metadata(match.group("value"), line_number)
            if metadata:
                self.tracked_vars[match.group("name")] = metadata

    def _find_sink(self, line: str) -> str | None:
        for sink, pattern in SINK_PATTERNS.items():
            if pattern.search(line):
                return sink
        return None

    def _inspect_sink(self, line: str, line_number: int) -> None:
        sink = self._find_sink(line)
        if not sink:
            return
        traced_variable = next((name for name in self.tracked_vars if re.search(rf"\b{re.escape(name)}\b", line)), None)
        if traced_variable:
            metadata = self.tracked_vars[traced_variable]
            self.findings.append({
                "line": line_number,
                "sink": sink,
                "kind": "traced_extension_sink" if sink == "chrome.tabs.executeScript" else "traced_execution_sink",
                "source_var": traced_variable,
                "source_line": metadata["line"],
                "entropy": metadata["entropy"],
            })
            return
        direct_match = next((match for match in STRING_PATTERN.finditer(line) if _blob_metadata(match.group("value"), line_number)), None)
        if direct_match:
            metadata = _blob_metadata(direct_match.group("value"), line_number)
            self.findings.append({
                "line": line_number,
                "sink": sink,
                "kind": "direct_extension_sink" if sink == "chrome.tabs.executeScript" else "direct_execution_sink",
                "source_line": line_number,
                "entropy": metadata["entropy"] if metadata else 0.0,
            })
            return
        self.findings.append({"line": line_number, "sink": sink, "kind": "extension_or_network"})

    def analyze(self) -> dict[str, Any]:
        for line_number, line in enumerate(self.source.splitlines(), start=1):
            self._track_assignments(line, line_number)
            self._inspect_sink(line, line_number)
        weights = {
            "traced_extension_sink": 75,
            "traced_execution_sink": 75,
            "direct_extension_sink": 50,
            "direct_execution_sink": 50,
            "extension_or_network": 15,
        }
        score = min(100, sum(weights.get(item["kind"], 0) for item in self.findings))
        return {"anomaly_score": score, "findings": [{"file": self.filename, **item} for item in self.findings], "files_scanned": 1}


def analyze_js_sources(sources: dict[str, str]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    total_score = 0
    for filename, source in sources.items():
        result = JSAnalyzer(source, filename).analyze()
        findings.extend(result["findings"])
        total_score += result["anomaly_score"]
    return {"anomaly_score": min(100, total_score), "findings": findings, "files_scanned": len(sources)}


def analyze_js_files(root: str | Path) -> dict[str, Any]:
    sources: dict[str, str] = {}
    for path in Path(root).rglob("*"):
        if path.suffix not in {".js", ".json"}:
            continue
        try:
            sources[str(path.relative_to(root))] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            LOGGER.error("[-] Could not read %s: %s", path, error)
    return analyze_js_sources(sources)
