import tempfile
from pathlib import Path

from git_hunter.analyzer import analyze_python_files, analyze_python_sources


def test_only_flags_payload_when_it_reaches_execution_sink():
    with tempfile.TemporaryDirectory() as directory:
        Path(directory, "sample.py").write_text("value = '" + "A" * 100 + "'\nprint(value)\n")
        result = analyze_python_files(directory)
    assert result["anomaly_score"] == 0
    assert result["findings"] == []


def test_traces_decoded_payload_to_sink():
    result = analyze_python_sources({"sample.py": "import base64\npayload = base64.b64decode('" + "A" * 100 + "')\nexec(payload)\n"})
    assert result["anomaly_score"] == 75
    assert result["findings"][0]["kind"] == "traced_execution_sink"
    assert result["findings"][0]["source_var"] == "payload"