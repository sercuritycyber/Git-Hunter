from git_hunter.bash_parser import analyze_bash_sources
from git_hunter.js_parser import analyze_js_sources


def test_bash_analyzer_includes_static_signatures():
    result = analyze_bash_sources({
        "callback.sh": "curl https://transfer.sh/upload\n",
    })

    assert result["anomaly_score"] == 60
    assert result["findings"][0]["kind"] == "static_signature_match"


def test_javascript_analyzer_includes_static_signatures():
    result = analyze_js_sources({
        "callback.js": "const url = 'https://pastebin.com/raw/example';\n",
    })

    assert result["anomaly_score"] == 60
    assert result["findings"][0]["kind"] == "static_signature_match"
