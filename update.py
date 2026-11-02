#!/usr/bin/env python3
"""Refresh SOCKS5, retaining the existing latency and throughput policy."""
import concurrent.futures
import os
import subprocess
import time

from subscription import (OUT, GEOIP_URL, canonical_socks, connectivity, curl, fetch_bytes,
                          healthy_targets, previous, publish, write_json)

SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
]
LIMIT = int(os.getenv("MAX_PROXIES", "100"))
CANDIDATES = int(os.getenv("MAX_CANDIDATES", "600"))
WORKERS = int(os.getenv("CHECK_WORKERS", "48"))
MAX_LATENCY_MS = int(os.getenv("MAX_LATENCY_MS", "3500"))
MIN_SPEED_MBPS = float(os.getenv("MIN_SPEED_MBPS", "0.25"))
SPEED_TEST_LIMIT = int(os.getenv("SPEED_TEST_LIMIT", "80"))
SPEED_TEST_BYTES = int(os.getenv("SPEED_TEST_BYTES", "262144"))


def collect():
    def source(url):
        try:
            body = fetch_bytes(url)
            found = set()
            for line in body.decode("utf-8-sig").splitlines():
                try:
                    found.add(canonical_socks(line))
                except (ValueError, TypeError):
                    continue
            if body.strip() and not found:
                raise ValueError("unrecognized SOCKS source")
            return found, True
        except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
            return set(), False
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        fetched = list(pool.map(source, SOURCES))
    found = dict.fromkeys(uri for items, _ in fetched for uri in sorted(items))
    return list(found)[:CANDIDATES], sum(ok for _, ok in fetched)


def check(uri, targets, deadline=None):
    if deadline is not None and time.monotonic() + 16 > deadline:
        return uri, "not_tested", None
    outcome, latency = connectivity(uri.replace("socks://", "socks5h://", 1), targets)
    if outcome == "passed" and latency > MAX_LATENCY_MS:
        outcome = "latency_rejected"
    return uri, outcome, latency


def speed_test(item):
    uri, _, latency = item
    try:
        result = curl(["--proxy", uri.replace("socks://", "socks5h://", 1), "--noproxy", "",
                       "--output", os.devnull, "--max-filesize", str(SPEED_TEST_BYTES),
                       "--write-out", "%{http_code} %{size_download} %{time_total} %{time_starttransfer}",
                       f"https://speed.cloudflare.com/__down?bytes={SPEED_TEST_BYTES}"], 10)
        code, size, total, first = result.stdout.decode().split()
        seconds = float(total) - float(first)
        if result.returncode or code != "200" or int(size) != SPEED_TEST_BYTES or seconds <= 0:
            return uri, "inconclusive", None
        speed = int(size) * 8 / seconds / 1_000_000
        return uri, "passed" if speed >= MIN_SPEED_MBPS else "speed_rejected", speed
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return uri, "inconclusive", None


def main():
    deadline = time.monotonic() + 100
    old_state, old_nodes = previous("socks", canonical_socks)
    candidates, success = collect()
    candidates = list(dict.fromkeys([*candidates, *old_nodes]))
    targets = healthy_targets()
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        initial = list(pool.map(lambda uri: check(uri, targets, deadline - 40), candidates))
    eligible = sorted((item for item in initial if item[1] == "passed"), key=lambda item: item[2])
    chosen = eligible[:SPEED_TEST_LIMIT]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        measured = list(pool.map(lambda item: speed_test(item) if time.monotonic() + 11 < deadline
                                 else (item[0], "inconclusive", None), chosen))
    passed = sorted((item for item in measured if item[1] == "passed"), key=lambda item: -item[2])[:LIMIT]
    outcomes = passed + [item for item in initial if item[1] != "passed"]
    outcomes += [item for item in measured if item[1] != "passed"]
    status, nodes = publish("socks", "proxies.txt", outcomes, old_nodes, success, old_state,
                            {"candidates": len(candidates), "successful_sources": success,
                             "alive": sum(item[1] in ("passed", "latency_rejected") for item in initial),
                             "speed_tested": len(chosen), "min_speed_mbps": MIN_SPEED_MBPS,
                             "max_latency_ms": MAX_LATENCY_MS, "healthy_test_targets": len(targets),
                             "fallback_reason": "upstream/check incomplete; recent verified cache only"})
    if len(nodes) > LIMIT:
        selected = dict(list(nodes.items())[:LIMIT])
        from subscription import atomic_write, lines
        kept = [line for line in lines(OUT / "proxies.txt") if canonical_socks(line) in selected]
        atomic_write(OUT / "proxies.txt", "\n".join(kept) + ("\n" if kept else ""))
        write_json(OUT / "socks_state.json", {"last_success_at": status["last_success_at"], "nodes": selected})
        status["published"] = status["published_count"] = len(selected)
    write_json(OUT / "status.json", status)
    print("SOCKS:", {k: status[k] for k in ("candidates", "published", "results")})


if __name__ == "__main__":
    main()
