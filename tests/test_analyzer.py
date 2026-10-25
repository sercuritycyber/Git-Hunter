import tempfile
from pathlib import Path

from git_hunter.analyzer import analyze_python_files


def test_detects_execution_sink_and_base64():
    with tempfile.TemporaryDirectory() as directory:
        Path(directory, "sample.py").write_text("import os\nvalue = '" + "A" * 100 + "'\nos.system(value)\n")
        result = analyze_python_files(directory)
    assert result["anomaly_score"] > 0
    assert {finding["kind"] for finding in result["findings"]} == {"execution_or_network", "high_entropy_base64"}