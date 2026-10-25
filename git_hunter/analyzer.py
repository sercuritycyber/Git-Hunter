from __future__ import annotations

import ast
import logging
import math
import re
from pathlib import Path
from typing import Any


LOGGER = logging.getLogger(__name__)
SINKS = {"eval", "exec", "compile", "__import__", "system", "popen", "check_output", "run", "urlopen", "request"}
BASE64 = re.compile(r"^[A-Za-z0-9+/=]{80,}$")
ENTROPY_THRESHOLD = 5.5


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _base64_metadata(value: str, line: int) -> dict[str, Any] | None:
    candidate = value.strip()
    if not BASE64.fullmatch(candidate):
        return None
    entropy = _entropy(candidate)
    if entropy <= ENTROPY_THRESHOLD:
        return None
    return {"line": line, "entropy": entropy}


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, source: str, filename: str) -> None:
        self.source = source
        self.filename = filename
        self.findings: list[dict[str, Any]] = []
        self.tracked_vars: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    def _payload_metadata(self, node: ast.AST) -> dict[str, Any] | None:
        if isinstance(node, ast.Name):
            return self.tracked_vars.get(node.id)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return _base64_metadata(node.value, node.lineno)
        if isinstance(node, ast.Call) and self._call_name(node) in {"b64decode", "urlsafe_b64decode"} and node.args:
            return self._payload_metadata(node.args[0])
        return None

    def visit_Assign(self, node: ast.Assign) -> Any:
        payload = self._payload_metadata(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if payload:
                    self.tracked_vars[target.id] = payload
                else:
                    self.tracked_vars.pop(target.id, None)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        name = self._call_name(node)
        if name in SINKS:
            traced = next((self._payload_metadata(argument) for argument in node.args if self._payload_metadata(argument)), None)
            if traced:
                source_var = next((argument.id for argument in node.args if isinstance(argument, ast.Name) and argument.id in self.tracked_vars), None)
                self.findings.append({
                    "line": node.lineno,
                    "sink": name,
                    "kind": "traced_execution_sink" if source_var else "direct_execution_sink",
                    "source_var": source_var,
                    "source_line": traced["line"],
                    "entropy": traced["entropy"],
                })
            else:
                self.findings.append({"line": node.lineno, "sink": name, "kind": "execution_or_network"})
        self.generic_visit(node)


def analyze_python_sources(sources: dict[str, str]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for filename, source in sources.items():
        try:
            tree = ast.parse(source, filename=filename)
        except (SyntaxError, UnicodeDecodeError) as error:
            LOGGER.error("[-] Malformed Python in %s: %s", filename, error)
            findings.append({"file": filename, "line": getattr(error, "lineno", 0) or 0, "sink": None, "kind": "malformed_python"})
            continue
        analyzer = PythonAnalyzer(source, filename)
        analyzer.visit(tree)
        findings.extend({"file": filename, **finding} for finding in analyzer.findings)
    weights = {"traced_execution_sink": 75, "direct_execution_sink": 50, "execution_or_network": 15, "malformed_python": 50}
    score = min(100, sum(weights.get(finding["kind"], 0) for finding in findings))
    return {"anomaly_score": score, "findings": findings, "files_scanned": len(sources)}


def analyze_python_files(root: str | Path) -> dict[str, Any]:
    sources: dict[str, str] = {}
    for path in Path(root).rglob("*.py"):
        try:
            sources[str(path.relative_to(root))] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            LOGGER.error("[-] Could not read %s: %s", path, error)
    return analyze_python_sources(sources)


def markdown_report(repo: str, result: dict[str, Any], ai_analysis: str | None = None) -> str:
    lines = [f"# Scan report: {repo}", "", f"**Anomaly score:** {result['anomaly_score']}/100", "", "## Findings"]
    for item in result["findings"]:
        if item["kind"] == "traced_execution_sink":
            detail = f"`{item['source_var']}` from line {item['source_line']} (entropy {item['entropy']:.2f}) -> `{item['sink']}`"
        elif item["sink"]:
            detail = f"{item['kind']} -> `{item['sink']}`"
        else:
            detail = item["kind"]
        lines.append(f"- `{item['file']}:{item['line']}`: {detail}")
    lines.append(f"\n## AI analysis\n{ai_analysis or 'Unavailable'}")
    return "\n".join(lines)
