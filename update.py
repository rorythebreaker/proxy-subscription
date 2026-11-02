#!/usr/bin/env python3
"""Refresh SOCKS5 with repeated gentle latency and throughput checks."""
import concurrent.futures
import os
import subprocess
import time

from subscription import (OUT, canonical_socks, connectivity, fetch_bytes,
                          healthy_targets, previous, publish, write_json, filter_quality, speed_baseline,
                          MIN_SPEED_MBPS, MAX_LATENCY_MS)

SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
]
LIMIT = int(os.getenv("MAX_PROXIES", "100"))
CANDIDATES = int(os.getenv("MAX_CANDIDATES", "600"))
WORKERS = int(os.getenv("CHECK_WORKERS", "48"))


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


def check(uri, targets, deadline=None, baseline_ok=False):
    if deadline is not None and time.monotonic() + 35 > deadline:
        return uri, "not_tested", None
    proxy = uri.replace("socks://", "socks5h://", 1)
    outcome, latency = connectivity(proxy, targets)
    if outcome == "passed":
        outcome, latency = filter_quality(proxy, targets, latency, baseline_ok, deadline)
    return uri, outcome, latency


def main():
    deadline = time.monotonic() + 100
    old_state, old_nodes = previous("socks", canonical_socks)
    candidates, success = collect()
    candidates = list(dict.fromkeys([*old_nodes, *candidates]))
    targets = healthy_targets()
    baseline_ok = speed_baseline() if len(targets) == 2 else False
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        initial = list(pool.map(lambda uri: check(uri, targets, deadline, baseline_ok), candidates))
    passed = sorted((item for item in initial if item[1] == "passed"), key=lambda item: item[2])[:LIMIT]
    outcomes = passed + [item for item in initial if item[1] != "passed"]
    status, nodes = publish("socks", "proxies.txt", outcomes, old_nodes, success, old_state,
                            {"candidates": len(candidates), "successful_sources": success,
                             "alive": sum(item[1] in ("passed", "latency_rejected", "speed_rejected", "quality_inconclusive") for item in initial),
                             "speed_baseline_ok": baseline_ok, "min_speed_mbps": MIN_SPEED_MBPS,
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
