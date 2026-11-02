#!/usr/bin/env python3
"""Collect and verify public SOCKS5 proxies; publish URI subscription."""
import concurrent.futures
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
import requests

SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
]
OUT = Path("public")
LIMIT = int(os.getenv("MAX_PROXIES", "100"))
CANDIDATES = int(os.getenv("MAX_CANDIDATES", "350"))
CHECK_URL = "https://www.gstatic.com/generate_204"

def collect():
    found = set()
    for url in SOURCES:
        try:
            response = requests.get(url, timeout=20)
            response.raise_for_status()
            for raw in response.text.splitlines():
                raw = raw.strip().removeprefix("socks5://").removeprefix("socks://")
                match = re.fullmatch(r"([\d.]+):(\d{1,5})", raw)
                if not match:
                    continue
                host, port = match.groups()
                try:
                    ip = ipaddress.ip_address(host)
                    if not ip.is_global or not 0 < int(port) < 65536:
                        continue
                except ValueError:
                    continue
                found.add(f"{host}:{port}")
            print(f"Fetched {url}: total unique {len(found)}")
        except requests.RequestException as exc:
            print(f"Source failed: {url}: {exc}")
    return sorted(found)[:CANDIDATES]

def check(proxy):
    try:
        resp = requests.get(CHECK_URL, proxies={
            "http": f"socks5h://{proxy}", "https": f"socks5h://{proxy}"
        }, timeout=(3, 6), allow_redirects=False)
        return proxy if resp.status_code == 204 else None
    except requests.RequestException:
        return None

def main():
    candidates = collect()
    print(f"Checking {len(candidates)} candidates")
    good = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
        for result in pool.map(check, candidates):
            if result:
                good.append(result)
                if len(good) >= LIMIT:
                    break
    OUT.mkdir(exist_ok=True)
    now = datetime.now(timezone.utc).isoformat()
    status = {"checked_at": now, "candidates": len(candidates), "alive": len(good), "sources": SOURCES}
    (OUT / "status.json").write_text(json.dumps(status, indent=2) + "\n")
    if not good:
        print("No live proxies. Keeping previous subscription.")
        return
    lines = [f"socks://{proxy}#{quote('SOCKS5-' + str(i).zfill(3) + '-' + proxy, safe='')}" for i, proxy in enumerate(good, 1)]
    (OUT / "proxies.txt").write_text("\n".join(lines) + "\n")
    (OUT / "alive.txt").write_text("\n".join(good) + "\n")
    print(f"Published {len(good)} proxies")

if __name__ == "__main__":
    main()
