#!/usr/bin/env python3
"""Refresh a SOCKS5 URI subscription with measured HTTPS latency."""
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
import geoip2.database
import tempfile

SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
]
OUT = Path("public")
LIMIT = int(os.getenv("MAX_PROXIES", "100"))
CANDIDATES = int(os.getenv("MAX_CANDIDATES", "350"))
WORKERS = int(os.getenv("CHECK_WORKERS", "48"))
CHECK_URL = "https://www.gstatic.com/generate_204"
MAX_LATENCY_MS = int(os.getenv("MAX_LATENCY_MS", "1500"))
MIN_SPEED_MBPS = float(os.getenv("MIN_SPEED_MBPS", "1.0"))
SPEED_TEST_LIMIT = int(os.getenv("SPEED_TEST_LIMIT", "50"))
SPEED_TEST_BYTES = int(os.getenv("SPEED_TEST_BYTES", "262144"))
SPEED_URL = "https://speed.cloudflare.com/__down?bytes="
GEOIP_URL = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"


def country_codes(proxies):
    """Resolve country from a local MMDB snapshot; fail open with ZZ."""
    if not proxies:
        return {}
    try:
        response = requests.get(GEOIP_URL, timeout=(10, 30))
        response.raise_for_status()
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "Country.mmdb"
            db_path.write_bytes(response.content)
            with geoip2.database.Reader(str(db_path)) as reader:
                result = {}
                for proxy, _ in proxies:
                    ip = proxy.rsplit(":", 1)[0]
                    try:
                        # Country.mmdb uses country ISO codes for IP prefixes.
                        result[proxy] = reader.country(ip).country.iso_code or "ZZ"
                    except (geoip2.errors.AddressNotFoundError, ValueError):
                        result[proxy] = "ZZ"
                return result
    except (requests.RequestException, OSError, ValueError) as exc:
        print(f"GeoIP unavailable: {exc}; using ZZ")
        return {proxy: "ZZ" for proxy, _ in proxies}



def collect():
    found = set()
    successful_sources = 0
    for url in SOURCES:
        try:
            response = requests.get(url, timeout=20)
            response.raise_for_status()
            successful_sources += 1
            for raw in response.text.splitlines():
                raw = raw.strip().removeprefix("socks5://").removeprefix("socks://")
                match = re.fullmatch(r"([\d.]+):(\d{1,5})", raw)
                if not match:
                    continue
                host, port = match.groups()
                try:
                    if not ipaddress.ip_address(host).is_global or not 0 < int(port) < 65536:
                        continue
                except ValueError:
                    continue
                found.add(f"{host}:{port}")
            print(f"Fetched {url}: {len(found)} unique candidates")
        except requests.RequestException as exc:
            print(f"Source failed: {url}: {exc}")
    return sorted(found)[:CANDIDATES], successful_sources


def check(proxy):
    start = time.monotonic()
    try:
        response = requests.get(
            CHECK_URL,
            proxies={"http": f"socks5h://{proxy}", "https": f"socks5h://{proxy}"},
            timeout=(3, 6),
            allow_redirects=False,
        )
        if response.status_code == 204:
            return proxy, round((time.monotonic() - start) * 1000)
    except requests.RequestException:
        pass
    return None


def speed_test(item):
    """Measure payload throughput through the SOCKS5 proxy, excluding setup time."""
    proxy, latency = item
    if latency > MAX_LATENCY_MS:
        return None
    try:
        with requests.get(
            f"{SPEED_URL}{SPEED_TEST_BYTES}",
            proxies={"http": f"socks5h://{proxy}", "https": f"socks5h://{proxy}"},
            timeout=(3, 8),
            stream=True,
            allow_redirects=False,
        ) as response:
            response.raise_for_status()
            if response.status_code != 200:
                return None
            total = 0
            started = time.monotonic()
            for chunk in response.iter_content(chunk_size=32768):
                if not chunk:
                    continue
                total += len(chunk)
                if total > SPEED_TEST_BYTES:
                    return None
            elapsed = time.monotonic() - started
            if total != SPEED_TEST_BYTES or elapsed <= 0:
                return None
            mbps = round(total * 8 / elapsed / 1_000_000, 2)
            if mbps >= MIN_SPEED_MBPS:
                return proxy, latency, mbps
    except (requests.RequestException, OSError, ValueError):
        pass
    return None


def main():
    candidates, successful_sources = collect()
    print(f"Checking {len(candidates)} candidates")
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = [result for result in pool.map(check, candidates) if result is not None]

    # Rank by end-to-end HTTPS latency, not ICMP ping or bandwidth.
    results.sort(key=lambda item: (item[1], item[0]))
    eligible = [item for item in results if item[1] <= MAX_LATENCY_MS]
    tested = eligible[:SPEED_TEST_LIMIT]
    print(f"Speed testing {len(tested)} proxies (min {MIN_SPEED_MBPS} Mbps)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(WORKERS, 16)) as pool:
        speed_results = [result for result in pool.map(speed_test, tested) if result]
    speed_results.sort(key=lambda item: (-item[2], item[1], item[0]))
    good = speed_results[:LIMIT]
    countries = country_codes([(proxy, latency) for proxy, latency, _ in good])
    OUT.mkdir(exist_ok=True)
    now = datetime.now(timezone.utc).isoformat()
    status = {
        "checked_at": now,
        "candidates": len(candidates),
        "alive": len(results),
        "published": len(good),
        "latency_passed": len(eligible),
        "speed_tested": len(tested),
        "speed_passed": len(speed_results),
        "min_speed_mbps": MIN_SPEED_MBPS,
        "max_latency_ms": MAX_LATENCY_MS,
        "speed_test_bytes": SPEED_TEST_BYTES,
        "fastest_speed_mbps": good[0][2] if good else None,
        "successful_sources": successful_sources,
        "latency_metric": "HTTPS GET via SOCKS5 to generate_204, milliseconds",
        "fastest_ms": min((item[1] for item in good), default=None),
        "sources": SOURCES,
        "geoip_database": GEOIP_URL,
        "country_unknown": sum(countries.get(proxy, "ZZ") == "ZZ" for proxy, _, _ in good),
    }
    (OUT / "status.json").write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")

    if successful_sources == 0:
        # A source outage is not evidence that previously published proxies failed.
        print("All sources failed; leaving existing subscription unchanged.")
        return

    # Empty output deliberately removes previously working proxies that no longer pass.
    lines = []
    for proxy, _, _ in good:
        ip = proxy.rsplit(':', 1)[0]
        label = f"{countries.get(proxy, 'ZZ')} {ip}"
        lines.append(f"socks://{proxy}#{quote(label, safe='')}")
    (OUT / "proxies.txt").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    (OUT / "alive.txt").write_text(
        "\n".join(proxy for proxy, _, _ in good) + ("\n" if good else ""),
        encoding="utf-8",
    )
    print(f"Published {len(good)} of {len(results)} live proxies")


if __name__ == "__main__":
    main()
