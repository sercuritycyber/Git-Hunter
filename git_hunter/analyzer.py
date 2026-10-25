from __future__ import annotations

import ast
import math
import re
from pathlib import Path
from typing import Any


SINKS = {"eval", "exec", "compile", "__import__", "system", "popen", "check_output", "run", "urlopen", "request"}
BASE64 = re.compile(r"[A-Za-z0-9+/=]{80,}")


def _entropy(value: str) -> float:
    counts = {char: value.count(char) for char in set(value)}
    if not value:
        return 0
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, source: str, filename: str) -> None:
        self.source, self.filename = source, filename
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
            value = node.value.strip()
            if len(value) >= 80 and BASE64.fullmatch(value):
                return {"line": node.lineno, "entropy": _entropy(value)}
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
            traced = next((self._payload_metadata(arg) for arg in node.args if self._payload_metadata(arg)), None)
            if traced:
                source = next((arg.id for arg in node.args if isinstance(arg, ast.Name) and arg.id in self.tracked_vars), None)
                self.findings.append({
                    "line": node.lineno,
                    "sink": name,
                    "kind": "traced_execution_sink" if source else "direct_execution_sink",
                    "source_var": source,
                    "source_line": traced["line"],
                    "entropy": traced["entropy"],
                })
            else:
                self.findings.append({"line": node.lineno, "sink": name, "kind": "execution_or_network"})
        self.generic_visit(node)


def analyze_python_sources(sources: dict[str, str]) -> dict[str, Any]:
    findings = []
    for filename, source in sources.items():
        try:
            tree = ast.parse(source, filename=filename)
        except (SyntaxError, UnicodeDecodeError):
            continue
        analyzer = PythonAnalyzer(source, filename)
        analyzer.visit(tree)
        findings.extend({"file": filename, **finding} for finding in analyzer.findings)
    score = sum({"traced_execution_sink": 75, "direct_execution_sink": 50, "execution_or_network": 15}.get(item["kind"], 0) for item in findings)
    return {"anomaly_score": min(100, score), "findings": findings, "files_scanned": len(sources)}


def analyze_python_files(root: str | Path) -> dict[str, Any]:
    sources = {}
    for path in Path(root).rglob("*.py"):
        try:
            sources[str(path.relative_to(root))] = path.read_text(encoding="utf-8")
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
    return analyze_python_sources(sources)


def markdown_report(repo: str, result: dict[str, Any], ai_analysis: str | None = None) -> str:
    lines = [f"# Scan report: {repo}", "", f"**Anomaly score:** {result['anomaly_score']}/100", "", "## Findings"]
    for item in result["findings"]:
        detail = f" -> `{item['sink']}`"
        if item["kind"] == "traced_execution_sink":
            detail = f": `{item['source_var']}` from line {item['source_line']} (entropy {item['entropy']:.2f}) -> `{item['sink']}`"
        lines.append(f"- `{item['file']}:{item['line']}`: `{item['kind']}`{detail}")
    lines.append(f"\n## AI analysis\n{ai_analysis or 'Unavailable'}")
    return "\n".join(lines)