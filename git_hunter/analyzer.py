from __future__ import annotations

import ast
import base64
import math
import re
from pathlib import Path
from typing import Any


SINKS = {"eval", "exec", "compile", "__import__", "system", "popen", "check_output", "run", "urlopen", "request"}
BASE64 = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


def _entropy(value: str) -> float:
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, source: str, filename: str) -> None:
        self.source, self.filename = source, filename
        self.findings: list[dict[str, Any]] = []

    def visit_Call(self, node: ast.Call) -> Any:
        name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if name in SINKS:
            self.findings.append({"line": node.lineno, "sink": name, "kind": "execution_or_network"})
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> Any:
        if isinstance(node.value, str) and len(node.value) >= 80 and BASE64.fullmatch(node.value.strip()):
            self.findings.append({"line": node.lineno, "sink": None, "kind": "high_entropy_base64", "entropy": _entropy(node.value)})


def analyze_python_files(root: str | Path) -> dict[str, Any]:
    findings = []
    for path in Path(root).rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        analyzer = PythonAnalyzer(path.read_text(encoding="utf-8"), str(path))
        analyzer.visit(tree)
        for finding in analyzer.findings:
            findings.append({"file": str(path.relative_to(root)), **finding})
    score = min(100, len(findings) * 15 + sum(35 for item in findings if item["sink"] and item["kind"] == "execution_or_network"))
    return {"anomaly_score": score, "findings": findings, "files_scanned": len(list(Path(root).rglob("*.py")))}


def markdown_report(repo: str, result: dict[str, Any], ai_analysis: str | None = None) -> str:
    lines = [f"# Scan report: {repo}", "", f"**Anomaly score:** {result['anomaly_score']}/100", "", "## Findings"]
    lines.extend(f"- `{item['file']}:{item['line']}`: `{item['kind']}`" + (f" -> `{item['sink']}`" if item["sink"] else "") for item in result["findings"])
    lines.append(f"\n## AI analysis\n{ai_analysis or 'Unavailable'}")
    return "\n".join(lines)