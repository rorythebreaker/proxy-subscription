"""Bounded network operations and freshness-aware subscription publication."""
import base64
import concurrent.futures
import ipaddress
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

OUT = Path(os.getenv("OUTPUT_DIR", "public"))
TTL = int(os.getenv("STALE_TTL_SECONDS", "600"))
MAX_LATENCY_MS = float(os.getenv("MAX_LATENCY_MS", "6000"))
MIN_SPEED_MBPS = float(os.getenv("MIN_SPEED_MBPS", "10"))
SPEED_TEST_BYTES = 2 * 1024 * 1024
SPEED_TEST_SECONDS = 14
QUALITY_POLICY = f"verified-speed-v2:{MAX_LATENCY_MS}:{MIN_SPEED_MBPS}:{SPEED_TEST_BYTES}"
TARGETS = ("https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204")
GEOIP_URL = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def age(value):
    try:
        return max(0, time.time() - datetime.fromisoformat(value).timestamp())
    except (TypeError, ValueError):
        return float("inf")


def load_json(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def write_json(path, value):
    atomic_write(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def lines(path):
    try:
        return [s.strip() for s in Path(path).read_text(encoding="utf-8").splitlines() if s.strip()]
    except OSError:
        return []


def curl(args, seconds=10):
    # curl enforces a total transfer deadline, unlike an idle read timeout.
    return subprocess.run(["curl", "--silent", "--show-error", "--max-time", str(seconds),
                           "--connect-timeout", str(min(4, seconds)), *args],
                          capture_output=True, timeout=seconds + 1)


def fetch_bytes(url, max_bytes=25_000_000):
    result = curl(["--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
                   "--proxy", "", "--noproxy", "*", "--max-filesize", str(max_bytes), url], 12)
    if result.returncode or len(result.stdout) > max_bytes:
        raise ValueError("download failed or exceeded size limit")
    return result.stdout


def decode_lines(body):
    text = body.decode("utf-8-sig").strip()
    if not text:
        return []  # A genuinely empty upstream is distinct from malformed content.
    if not re.search(r"(?m)^\s*[a-zA-Z][a-zA-Z0-9+.-]*://", text):
        compact = re.sub(r"\s+", "", text)
        text = base64.b64decode(compact + "=" * (-len(compact) % 4),
                                altchars=b"-_", validate=True).decode("utf-8")
    return text.splitlines()


def canonical_socks(value):
    value = value.strip()
    if "://" not in value:
        value = "socks://" + value
    p = urlsplit(value)
    if p.scheme not in ("socks", "socks5") or p.username is not None or p.path not in ("", "/") or p.query:
        raise ValueError("unsupported SOCKS URI")
    ip = ipaddress.ip_address(p.hostname)
    if not ip.is_global or not p.port or not 1 <= p.port <= 65535:
        raise ValueError("non-public endpoint or invalid port")
    host = f"[{ip}]" if ip.version == 6 else str(ip)
    return f"socks://{host}:{p.port}"


def probe(proxy, url, seconds=7):
    try:
        result = curl(["--proxy", proxy or "", "--noproxy", "" if proxy else "*",
                       "--output", os.devnull, "--write-out", "%{http_code} %{time_total}", url], seconds)
        status, elapsed = result.stdout.decode().split()
        if result.returncode == 0 and status == "204":
            return "passed", float(elapsed) * 1000
        # An HTTP response (including 403/429) proves a tunnel, not a dead proxy.
        return ("inconclusive" if result.returncode == 0 else "network_error"), None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return "inconclusive", None


def healthy_targets():
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda url: probe(None, url), TARGETS))
    return [url for url, result in zip(TARGETS, results) if result[0] == "passed"]


def connectivity(proxy, targets):
    if len(targets) != 2:
        return "inconclusive", None
    results = []
    for url in targets:
        outcome, latency = probe(proxy, url)
        if outcome == "passed":
            return outcome, latency
        results.append(outcome)
    return ("unreachable" if all(s == "network_error" for s in results) else "inconclusive"), None


def measure_speed(proxy=None):
    """Small bounded HTTPS payload; errors/blocks are unknown, never zero speed."""
    try:
        result = curl(["--proxy", proxy or "", "--noproxy", "" if proxy else "*",
                       "--output", os.devnull, "--max-filesize", str(SPEED_TEST_BYTES),
                       "--write-out", "%{http_code} %{size_download} %{time_total} %{time_starttransfer}",
                       f"https://speed.cloudflare.com/__down?bytes={SPEED_TEST_BYTES}"], SPEED_TEST_SECONDS)
        code, size, total, first = result.stdout.decode().split()
        seconds = float(total) - float(first)
        if code != "200" or seconds <= 0:
            return None
        # A partial timeout after HTTP 200 gives an observed payload transfer rate.
        if result.returncode not in (0, 28) or (result.returncode == 0 and int(size) != SPEED_TEST_BYTES):
            return None
        if int(size) <= 0:
            return None
        return int(size) * 8 / seconds / 1_000_000
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def speed_baseline():
    speed = measure_speed()
    return speed is not None and speed >= MIN_SPEED_MBPS * 4


def filter_quality(proxy, targets, latency, baseline_ok, deadline=None):
    """Require measured throughput; repeat slowness before confirming rejection."""
    def budget(seconds):
        return deadline is None or time.monotonic() + seconds < deadline

    if latency is not None and latency > MAX_LATENCY_MS:
        if not budget(16):
            return "quality_inconclusive", latency
        outcome, retry_latency = connectivity(proxy, list(reversed(targets)))
        if outcome == "passed" and retry_latency > MAX_LATENCY_MS:
            return "latency_rejected", retry_latency
        if outcome != "passed":
            return "quality_inconclusive", latency
        latency = retry_latency
    if not baseline_ok or not budget(SPEED_TEST_SECONDS + 1):
        return "quality_inconclusive", latency
    first = measure_speed(proxy)
    if first is None:
        return "quality_inconclusive", latency
    if first < MIN_SPEED_MBPS:
        if not budget(SPEED_TEST_SECONDS + 1):
            return "quality_inconclusive", latency
        second = measure_speed(proxy)
        if second is None:
            return "quality_inconclusive", latency
        if second < MIN_SPEED_MBPS:
            return "speed_rejected", latency
    return "passed", latency


def country_labels(uris):
    result = {uri: ("ZZ", urlsplit(uri).hostname) for uri in uris}
    if not uris:
        return result
    try:
        import geoip2.database
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "Country.mmdb"
            db.write_bytes(fetch_bytes(GEOIP_URL))
            with geoip2.database.Reader(str(db)) as reader:
                for uri in uris:
                    host = urlsplit(uri).hostname
                    try:
                        ipaddress.ip_address(host)
                        code = reader.country(host).country.iso_code or "ZZ"
                        result[uri] = (code.upper(), host)
                    except (ValueError, geoip2.errors.GeoIP2Error):
                        pass
    except Exception as exc:
        # Optional metadata must never prevent a verified list from being published.
        print("GeoIP unavailable:", type(exc).__name__)
    return result


def previous(kind, validator):
    state = load_json(OUT / f"{kind}_state.json")
    nodes = {}
    for uri, data in state.get("nodes", {}).items():
        try:
            core = validator(uri)
            if data.get("quality_policy") == QUALITY_POLICY and age(data.get("last_verified_at")) <= TTL:
                nodes[core] = data
        except (ValueError, TypeError, AttributeError):
            pass
    return state, nodes


def publish(kind, filename, outcomes, old_nodes, source_success, old_state, details):
    """Publish passes plus recent inconclusive cache; confirmed failures never survive."""
    now = timestamp()
    nodes = {}
    counts = {}
    for uri, outcome, _ in outcomes:
        counts[outcome] = counts.get(outcome, 0) + 1
        if outcome == "passed":
            nodes[uri] = {"last_verified_at": now, "quality_policy": QUALITY_POLICY}
        elif outcome not in ("unreachable", "invalid", "latency_rejected", "speed_rejected") and uri in old_nodes and old_nodes[uri].get("quality_policy") == QUALITY_POLICY and age(old_nodes[uri].get("last_verified_at")) <= TTL:
            nodes[uri] = old_nodes[uri]
    # Only records still inside the verification TTL can survive an interrupted batch.
    labels = country_labels(list(nodes))
    rendered = [f"{uri}#{quote(' '.join(labels[uri]), safe='')}" for uri in nodes]
    atomic_write(OUT / filename, "\n".join(rendered) + ("\n" if rendered else ""))
    last_success = now if source_success else old_state.get("last_success_at")
    write_json(OUT / f"{kind}_state.json", {"last_success_at": last_success, "nodes": nodes})
    stale = not source_success or any(data["last_verified_at"] != now for data in nodes.values())
    status = {**details, "attempted_at": now, "checked_at": now, "last_success_at": last_success,
              "published": len(nodes), "published_count": len(nodes), "new_count": counts.get("passed", 0),
              "stale": stale, "stale_ttl_seconds": TTL, "results": counts, "quality_policy": QUALITY_POLICY,
              "fallback_reason": details.get("fallback_reason") if stale else None}
    return status, nodes


def merge():
    from update_protocols import canonical_reality
    combined = {}
    counts = {}
    for kind, filename, validator in (("socks", "proxies.txt", canonical_socks),
                                      ("vless", "vless.txt", canonical_reality)):
        _, fresh = previous(kind, validator)
        kept = []
        for line in lines(OUT / filename):
            try:
                core = validator(line)
            except (ValueError, TypeError):
                continue
            if core in fresh and core not in combined:
                combined[core] = line
                kept.append(line)
        counts[kind] = len(kept)
        # Keep protocol files and all.txt consistent when expiring cached records.
        atomic_write(OUT / filename, "\n".join(kept) + ("\n" if kept else ""))
        status_path = OUT / ("status.json" if kind == "socks" else "protocol_status.json")
        status = load_json(status_path)
        target = status if kind == "socks" else status.setdefault("vless_reality", {})
        target["published"] = target["published_count"] = len(kept)
        write_json(status_path, status)
    atomic_write(OUT / "all.txt", "\n".join(combined.values()) + ("\n" if combined else ""))
    atomic_write(OUT / "alive.txt", "\n".join(urlsplit(line).netloc for line in lines(OUT / "proxies.txt"))
                 + ("\n" if counts.get("socks") else ""))
    (OUT / "shadowsocks.txt").unlink(missing_ok=True)
    from incy import build_subscription
    profiles, incy_status = build_subscription(combined.values())
    write_json(OUT / "incy.json", profiles)
    from xray_auto import build_auto, build_choices
    auto, auto_status = build_auto(combined.values())
    write_json(OUT / "xray-auto-only.json", auto)
    write_json(OUT / "xray-auto.json", build_choices(combined.values()))
    write_json(OUT / "combined_status.json", {"published_at": timestamp(), "counts": counts,
                                              "published": len(combined), "stale_ttl_seconds": TTL,
                                              "incy": incy_status, "xray_auto": auto_status})
