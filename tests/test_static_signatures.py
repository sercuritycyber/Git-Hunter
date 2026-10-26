from git_hunter.bash_parser import analyze_bash_sources
from git_hunter.analyzer import analyze_python_sources
from git_hunter.js_parser import analyze_js_sources


def test_bash_analyzer_includes_static_signatures():
    result = analyze_bash_sources({
        "callback.sh": "curl https://transfer.sh/upload\n",
    })

    assert result["anomaly_score"] == 60
    assert result["findings"][0]["kind"] == "static_signature_match"


def test_javascript_analyzer_includes_static_signatures():
    result = analyze_js_sources({
        "callback.js": "fetch('https://pastebin.com/raw/example');\n",
    })

    assert result["anomaly_score"] == 60
    assert result["findings"][0]["kind"] == "static_signature_match"


def test_callback_url_without_network_action_is_not_a_finding():
    result = analyze_python_sources({
        "config.py": "webhook_url = 'https://discord.com/api/webhooks/example'\n",
    })

    assert result["anomaly_score"] == 0
    assert result["findings"] == []


def test_bare_shell_and_browser_sinks_are_not_findings():
    bash = analyze_bash_sources({"safe.sh": "eval \"$USER_COMMAND\"\n"})
    javascript = analyze_js_sources({
        "safe.js": "const socket = new WebSocket(url);\n",
    })

    assert bash["anomaly_score"] == 0
    assert bash["findings"] == []
    assert javascript["anomaly_score"] == 0
    assert javascript["findings"] == []


def test_repetitive_blobs_are_not_treated_as_encoded_payloads():
    blob = "A" * 100
    bash = analyze_bash_sources({"safe.sh": f"payload={blob}\neval \"$payload\"\n"})
    javascript = analyze_js_sources({
        "safe.js": f'const payload = "{blob}";\neval(payload);\n',
    })

    assert bash["anomaly_score"] == 0
    assert bash["findings"] == []
    assert javascript["anomaly_score"] == 0
    assert javascript["findings"] == []


def test_unrelated_post_text_does_not_activate_callback_signature():
    from git_hunter.signatures import scan_source

    assert scan_source(
        "post = 'https://discord.com/api/webhooks/example'\n"
    ) == []


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
