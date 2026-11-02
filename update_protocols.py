#!/usr/bin/env python3
"""Collect VLESS+REALITY and verify full HTTPS tunnels with gentle quality gates."""
import base64
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

from subscription import (OUT, connectivity, decode_lines, fetch_bytes, healthy_targets,
                          previous, publish, timestamp, write_json, filter_quality,
                          speed_baseline, MIN_SPEED_MBPS, MAX_LATENCY_MS)

SOURCES = {"vless_reality": [
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/vless.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/reality.txt",
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/main/protocols/vless.txt",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
]}
MAX_ITEMS = int(os.getenv("MAX_PROTOCOL_NODES", "1000"))
MAX_CHECKS = int(os.getenv("MAX_PROTOCOL_CHECKS", "240"))
WORKERS = int(os.getenv("PROTOCOL_WORKERS", "24"))


class Unsupported(ValueError):
    """URI whose semantics this verifier cannot reproduce."""


def parse_reality(uri):
    p = urlsplit(uri.strip())
    if p.scheme != "vless" or not p.hostname or not p.port or p.password is not None or p.path not in ("", "/"):
        raise ValueError("invalid VLESS authority")
    user = str(uuid.UUID(p.username))
    try:
        address = ipaddress.ip_address(p.hostname)
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", p.hostname):
            raise ValueError("invalid hostname")
        if p.hostname.lower() == "localhost" or p.hostname.lower().endswith((".localhost", ".local")):
            raise ValueError("local endpoint")
    else:
        if not address.is_global:
            raise ValueError("non-public endpoint")
    pairs = parse_qsl(p.query, keep_blank_values=True, strict_parsing=True)
    q = dict(pairs)
    if len(q) != len(pairs):
        raise ValueError("duplicate query parameters")
    if q.get("security", "").lower() != "reality" or not q.get("sni"):
        raise ValueError("missing REALITY settings")
    key = q.get("pbk", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", key) or len(base64.b64decode(key + "=", altchars=b"-_", validate=True)) != 32:
        raise ValueError("invalid REALITY public key")
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", q.get("sid", "")):
        raise ValueError("invalid short ID")
    if any(c.isspace() for c in q["sni"]) or any(c in q["sni"] for c in "/?#@"):
        raise ValueError("invalid SNI")
    q["security"] = "reality"
    if not q.get("fp"):
        q["fp"] = "chrome"
    host = f"[{p.hostname}]" if ":" in p.hostname else p.hostname.lower()
    core = f"vless://{user}@{host}:{p.port}?{urlencode(sorted(q.items()))}"
    return core, p, q


def canonical_reality(uri):
    try:
        return parse_reality(uri)[0]
    except (TypeError, AttributeError) as exc:
        raise ValueError("invalid VLESS URI") from exc


def valid_reality(uri):
    try:
        canonical_reality(uri)
        return True
    except ValueError:
        return False


def as_outbound(uri):
    _, p, q = parse_reality(uri)
    known = {"security", "pbk", "sni", "sid", "fp", "flow", "type", "encryption", "alpn",
             "headerType", "host", "path", "serviceName", "mode", "ed", "eh", "spx"}
    if set(q) - known:
        raise Unsupported("unknown connection parameters")
    if q.get("encryption", "none") not in ("", "none"):
        raise Unsupported("VLESS encryption unsupported by sing-box")
    if q.get("headerType", "none") not in ("", "none"):
        raise Unsupported("TCP header obfuscation unsupported")
    flow = q.get("flow", "")
    if flow not in ("", "xtls-rprx-vision"):
        raise Unsupported("unsupported flow")
    transport = q.get("type", "tcp") or "tcp"
    if transport == "raw":
        transport = "tcp"
    if transport not in ("tcp", "ws", "grpc", "http", "h2", "httpupgrade"):
        raise Unsupported("unsupported transport")
    if flow and transport != "tcp":
        raise Unsupported("Vision requires TCP")
    if q["fp"] not in ("chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"):
        raise Unsupported("unsupported TLS fingerprint")
    outbound = {"type": "vless", "tag": "remote", "server": p.hostname,
                "server_port": p.port, "uuid": str(uuid.UUID(p.username)),
                "tls": {"enabled": True, "server_name": q["sni"],
                        "utls": {"enabled": True, "fingerprint": q["fp"]},
                        "reality": {"enabled": True, "public_key": q["pbk"], "short_id": q.get("sid", "")}}}
    if flow:
        outbound["flow"] = flow
    if q.get("alpn"):
        outbound["tls"]["alpn"] = q["alpn"].split(",")
    host, path = q.get("host", ""), q.get("path", "/") or "/"
    if transport == "ws":
        options = {"type": "ws", "path": path}
        if host:
            options["headers"] = {"Host": host}
        if q.get("ed"):
            if not q["ed"].isdigit():
                raise ValueError("invalid early data size")
            options["max_early_data"] = int(q["ed"])
            options["early_data_header_name"] = q.get("eh", "Sec-WebSocket-Protocol")
        outbound["transport"] = options
    elif transport == "grpc":
        if q.get("mode", "gun") not in ("", "gun"):
            raise Unsupported("unsupported gRPC mode")
        outbound["transport"] = {"type": "grpc", "service_name": q.get("serviceName", "")}
    elif transport in ("http", "h2"):
        outbound["transport"] = {"type": "http", "host": host.split(",") if host else [], "path": path}
    elif transport == "httpupgrade":
        outbound["transport"] = {"type": "httpupgrade", "host": host, "path": path}
    allowed = {"tcp": set(), "ws": {"host", "path", "ed", "eh"},
               "grpc": {"serviceName", "mode"}, "http": {"host", "path"},
               "h2": {"host", "path"}, "httpupgrade": {"host", "path"}}[transport]
    if any(q.get(k) for k in {"host", "path", "serviceName", "mode", "ed", "eh"} - allowed):
        raise Unsupported("transport parameters cannot be reproduced")
    return outbound


def collect(kind="vless_reality"):
    def source(url):
        try:
            body = fetch_bytes(url)
            decoded = decode_lines(body)
            meaningful = [line.strip() for line in decoded if line.strip() and not line.lstrip().startswith("#")]
            if meaningful and not any(re.match(r"^[a-zA-Z][\w+.-]*://", line) for line in meaningful):
                raise ValueError("unrecognized subscription")
            if body.strip() and not meaningful:
                raise ValueError("no recognizable subscription records")
            valid = []
            for line in meaningful:
                try:
                    valid.append(canonical_reality(line))
                except ValueError:
                    continue
            return valid, True
        except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
            return [], False
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        fetched = list(pool.map(source, SOURCES[kind]))
    found = {}
    lists = [iter(items) for items, _ in fetched]
    while lists and len(found) < MAX_ITEMS:
        remaining = []
        for iterator in lists:
            try:
                uri = next(iterator)
            except StopIteration:
                continue
            found.setdefault(uri, uri)
            remaining.append(iterator)
            if len(found) >= MAX_ITEMS:
                break
        lists = remaining
    return list(found), sum(success for _, success in fetched)


def config_for(remote, port):
    return {"log": {"level": "error"},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [remote]}


def diagnostic(stderr):
    """Return a safe category rather than logging credentials/configuration text."""
    text = stderr.decode("utf-8", errors="replace").lower()
    for marker, category in (("public_key", "public_key"), ("short_id", "short_id"),
                             ("utls", "utls"), ("fingerprint", "fingerprint"),
                             ("address already in use", "port_busy"),
                             ("transport", "transport"), ("flow", "flow")):
        if marker in text:
            return category
    return "other"


def verify(uri, targets, deadline=None, baseline_ok=False):
    if deadline is not None and time.monotonic() + 35 > deadline:
        return uri, "not_tested", None
    try:
        remote = as_outbound(uri)
    except Unsupported:
        return uri, "unsupported", None
    except (ValueError, TypeError):
        return uri, "invalid", None
    if len(targets) != 2:
        return uri, "inconclusive", None
    process = None
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "config.json"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        path.write_text(json.dumps(config_for(remote, port)), encoding="utf-8")
        try:
            checked = subprocess.run(["sing-box", "check", "-c", str(path)], capture_output=True, timeout=3)
            if checked.returncode:
                return uri, "config_error:" + diagnostic(checked.stderr[:4096]), None
            with (Path(folder) / "stderr.log").open("wb") as stderr:
                process = subprocess.Popen(["sing-box", "run", "-c", str(path)],
                                           stdout=subprocess.DEVNULL, stderr=stderr)
                for _ in range(20):
                    if process.poll() is not None:
                        stderr.flush()
                        return uri, "runtime_error:" + diagnostic((Path(folder) / "stderr.log").read_bytes()[:4096]), None
                    with socket.socket() as sock:
                        sock.settimeout(0.1)
                        if sock.connect_ex(("127.0.0.1", port)) == 0:
                            break
                    time.sleep(0.05)
                else:
                    return uri, "runtime_error", None
                proxy = f"socks5h://127.0.0.1:{port}"
                outcome, latency = connectivity(proxy, targets)
                if outcome == "passed":
                    outcome, latency = filter_quality(proxy, targets, latency, baseline_ok, deadline)
                return uri, outcome, latency
        except (OSError, subprocess.TimeoutExpired):
            return uri, "inconclusive", None
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    deadline = time.monotonic() + 180
    old_state, old_nodes = previous("vless", canonical_reality)
    uris, success = collect()
    targets = healthy_targets() if shutil.which("sing-box") else []
    baseline_ok = speed_baseline() if len(targets) == 2 else False
    candidates = [uri for uri in uris if uri not in old_nodes]
    offset = (int(time.time() // 300) * MAX_CHECKS) % len(candidates) if candidates else 0
    candidates = candidates[offset:] + candidates[:offset]
    # Recheck published nodes before rotating new candidates, rather than carrying
    # old nodes through several batches without attempting a connection.
    chosen = list(old_nodes)[:MAX_CHECKS]
    chosen += candidates[:max(0, MAX_CHECKS - len(chosen))]
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        outcomes = list(pool.map(lambda uri: verify(uri, targets, deadline, baseline_ok), chosen))
    chosen_set = set(chosen)
    outcomes.extend((uri, "inconclusive", None) for uri in old_nodes if uri not in chosen_set)
    tested = sum(item[1] in ("passed", "unreachable", "inconclusive", "latency_rejected", "speed_rejected", "quality_inconclusive") for item in outcomes[:len(chosen)]) if len(targets) == 2 else 0
    details = {"sources_reached": success, "candidates": len(uris), "tested": tested,
               "unexamined": max(0, len(candidates) + len(old_nodes) - len(chosen)), "max_checks": MAX_CHECKS,
               "healthy_test_targets": len(targets), "min_mbps": MIN_SPEED_MBPS,
               "max_latency_ms": MAX_LATENCY_MS, "speed_baseline_ok": baseline_ok,
               "fallback_reason": "upstream/check incomplete; recent verified cache only"}
    status, _ = publish("vless", "vless.txt", outcomes, old_nodes, success, old_state, details)
    write_json(OUT / "protocol_status.json", {"checked_at": timestamp(),
               "verification": "sing-box HTTPS; two targets on failure; two slow samples before quality rejection",
               "vless_reality": status})
    print("VLESS:", {k: status[k] for k in ("candidates", "tested", "published", "results")})


if __name__ == "__main__":
    main()
