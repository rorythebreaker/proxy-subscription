#!/usr/bin/env python3
"""Collect public SS and VLESS+REALITY URI subscriptions.

These are format-validated upstream configurations, NOT locally speed-tested.
"""
import base64
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, quote, unquote

import requests

SOURCES = {
    "shadowsocks": [
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    ],
    "vless_reality": [
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    ],
}
OUT = Path("public")
MAX_ITEMS = int(os.getenv("MAX_PROTOCOL_NODES", "150"))
MAX_SOURCE_BYTES = 8_000_000


def decode_lines(body):
    text = body.decode("utf-8-sig", errors="replace").strip()
    if "://" not in text[:2048]:
        try:
            raw = base64.b64decode(re.sub(r"\\s+", "", text) + "==", validate=False)
            text = raw.decode("utf-8")
        except (ValueError, UnicodeError):
            return []
    return text.splitlines()


def valid_ss(uri):
    try:
        parts = urlsplit(uri)
        if parts.scheme != "ss" or not parts.hostname or not parts.port:
            return False
        # SS SIP002 permits base64 userinfo or method:password userinfo.
        credentials = parts.netloc.rsplit("@", 1)
        if len(credentials) != 2 or not credentials[0]:
            return False
        userinfo = unquote(credentials[0])
        if ":" not in userinfo:
            userinfo = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
        method, sep, password = userinfo.partition(":")
        return bool(sep and method and password)
    except (ValueError, UnicodeError):
        return False


def valid_reality(uri):
    try:
        parts = urlsplit(uri)
        if parts.scheme != "vless" or not parts.hostname or not parts.port or not parts.username:
            return False
        params = parse_qs(parts.query)
        return (
            params.get("security", [""])[0].lower() == "reality"
            and bool(params.get("pbk", [""])[0])
            and bool(params.get("sni", [""])[0])
        )
    except ValueError:
        return False


def collect(kind):
    found = {}
    succeeded = 0
    for url in SOURCES[kind]:
        try:
            response = requests.get(url, timeout=(8, 22))
            response.raise_for_status()
            if len(response.content) > MAX_SOURCE_BYTES:
                raise ValueError("source too large")
            succeeded += 1
            for line in decode_lines(response.content):
                uri = line.strip()
                if kind == "shadowsocks" and not valid_ss(uri):
                    continue
                if kind == "vless_reality" and not valid_reality(uri):
                    continue
                # Preserve credentials and all transport parameters; normalize only label.
                core = uri.split("#", 1)[0]
                found.setdefault(core, core)
                if len(found) >= MAX_ITEMS:
                    break
        except (requests.RequestException, ValueError) as exc:
            print(f"{kind}: upstream unavailable ({type(exc).__name__})")
    return list(found.values()), succeeded


def main():
    OUT.mkdir(exist_ok=True)
    stats = {"checked_at": datetime.now(timezone.utc).isoformat(),
             "verification": "URI syntax only; upstream claims are not independently verified"}
    names = {"shadowsocks": "shadowsocks.txt", "vless_reality": "vless.txt"}
    for kind, filename in names.items():
        uris, success = collect(kind)
        stats[kind] = {"sources_reached": success, "published": len(uris)}
        if success:
            # Do not mislabel nodes by country: endpoint hostname can differ from exit IP.
            lines = [f"{uri}#{quote(('SS' if kind == 'shadowsocks' else 'VLESS-REALITY') + ' ' + str(i), safe='')}"
                     for i, uri in enumerate(uris, 1)]
            (OUT / filename).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        else:
            print(f"{kind}: keeping last published file")
    # Combined file uses the latest published protocol lists, even if one upstream failed.
    combined = []
    for filename in ("proxies.txt", "shadowsocks.txt", "vless.txt"):
        path = OUT / filename
        if path.exists():
            combined.extend(line for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    (OUT / "all.txt").write_text("\n".join(combined) + ("\n" if combined else ""), encoding="utf-8")
    (OUT / "protocol_status.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    print("Protocol collection:", {k: stats[k]["published"] for k in names})


if __name__ == "__main__":
    main()
