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


def test_python_reverse_shell_and_exfiltration_signatures():
    from git_hunter.signatures import scan_source

    findings = scan_source(
        "import socket; subprocess.dup2(sock, 0)\n"
        "https://discord.com/api/webhooks/123456/token\n"
        "https://api.telegram.org/bot123:token/sendMessage\n"
    )

    names = {finding["detail"] for finding in findings}
    assert "Matched signature: Python reverse shell socket" in names
    assert "Matched signature: Discord webhook exfiltration" in names
    assert "Matched signature: Telegram bot API exfiltration" in names


def test_static_signature_weights_match_proposed_severity():
    from git_hunter.signatures import scan_source

    findings = scan_source("curl https://discord.com/api/webhooks/123/token\n")

    assert findings[0]["weight"] == 60
