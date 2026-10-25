from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    name: str
    pattern: re.Pattern[str]
    weight: int


NETWORK_CALLBACKS = {
    "discord_webhook": "discord.com/api/webhooks",
    "pastebin_raw": "pastebin.com/raw/",
    "ngrok": "ngrok.io",
    "transfer_sh": "transfer.sh",
}

SIGNATURES = (
    Signature(
        "Netcat reverse shell",
        re.compile(r"nc\s+(?:-[a-zA-Z]+\s+)*-e\s+/bin/(?:ba)?sh"),
        80,
    ),
    Signature(
        "Bash TCP reverse shell",
        re.compile(r"bash\s+-i\s+>&\s+/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+"),
        80,
    ),
    Signature(
        "PowerShell WebClient download",
        re.compile(r"Net\.WebClient\)\.DownloadString"),
        80,
    ),
    Signature(
        "PowerShell execution bypass",
        re.compile(r"-NoP.*-Exec.*Bypass", re.IGNORECASE),
        80,
    ),
    Signature(
        "Hex escape density",
        re.compile(r"(?:\\x[0-9a-fA-F]{2}){10,}"),
        30,
    ),
    Signature(
        "chr concatenation obfuscation",
        re.compile(r"(?:chr\(\d+\)\.){5,}"),
        30,
    ),
)

for callback_name, domain in NETWORK_CALLBACKS.items():
    SIGNATURES += (
        Signature(
            f"{callback_name} callback",
            re.compile(re.escape(domain), re.IGNORECASE),
            60,
        ),
    )


def scan_source(source_code: str) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for line_number, line in enumerate(source_code.splitlines(), start=1):
        for signature in SIGNATURES:
            if signature.pattern.search(line):
                findings.append({
                    "line": line_number,
                    "kind": "static_signature_match",
                    "detail": f"Matched signature: {signature.name}",
                    "weight": signature.weight,
                })
    return findings
