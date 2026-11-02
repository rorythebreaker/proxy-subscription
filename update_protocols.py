#!/usr/bin/env python3
"""Collect public VLESS+REALITY URI subscriptions.

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
import geoip2.database
import subprocess
import socket
import tempfile
import time
import uuid

SOURCES = {
    "vless_reality": [
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    ],
}
OUT = Path("public")
MAX_ITEMS = int(os.getenv("MAX_PROTOCOL_NODES", "150"))
MAX_SOURCE_BYTES = 8_000_000
MAX_CHECKS = int(os.getenv("MAX_PROTOCOL_CHECKS", "24"))
MAX_LATENCY_MS = 1500
MIN_MBPS = 1.0


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


def as_outbound(uri):
    try:
        p = urlsplit(uri)
        if not p.hostname or not p.port:
            return None
        if p.scheme == "ss":
            user = unquote(p.netloc.rsplit("@", 1)[0])
            if ":" not in user:
                user = base64.urlsafe_b64decode(user + "=" * (-len(user) % 4)).decode()
            method, password = user.split(":", 1)
            if not method or not password:
                return None
            return {"type": "shadowsocks", "tag": "remote", "server": p.hostname,
                    "server_port": p.port, "method": method, "password": password}
        if p.scheme == "vless":
            q = parse_qs(p.query)
            get = lambda key, default="": q.get(key, [default])[0]
            if get("security").lower() != "reality" or not get("pbk") or not get("sni"):
                return None
            if get("type", "tcp") != "tcp":
                return None
            uuid.UUID(p.username)
            outbound = {"type": "vless", "tag": "remote", "server": p.hostname,
                        "server_port": p.port, "uuid": p.username,
                        "tls": {"enabled": True, "server_name": get("sni"),
                                "reality": {"enabled": True, "public_key": get("pbk"),
                                            "short_id": get("sid")}}}
            if get("fp"):
                outbound["tls"]["utls"] = {"enabled": True, "fingerprint": get("fp")}
            if get("flow"):
                outbound["flow"] = get("flow")
            return outbound
    except (ValueError, UnicodeError, IndexError):
        return None
    return None


def verify(uri):
    remote = as_outbound(uri)
    if remote is None:
        return None
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config = {"log": {"level": "error"},
              "inbounds": [{"type": "socks", "tag": "local", "listen": "127.0.0.1",
                            "listen_port": port}],
              "outbounds": [remote]}
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "config.json"
        path.write_text(json.dumps(config))
        process = subprocess.Popen(["sing-box", "run", "-c", str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(20):
                if process.poll() is not None:
                    return None
                with socket.socket() as sock:
                    if sock.connect_ex(("127.0.0.1", port)) == 0:
                        break
                time.sleep(0.1)
            else:
                return None
            session = requests.Session()
            session.trust_env = False
            proxy = f"socks5h://127.0.0.1:{port}"
            session.proxies = {"http": proxy, "https": proxy}
            start = time.monotonic()
            response = session.get("https://www.gstatic.com/generate_204", timeout=(3, 5))
            latency = (time.monotonic() - start) * 1000
            if response.status_code != 204 or latency > MAX_LATENCY_MS:
                return None
            with session.get("https://speed.cloudflare.com/__down?bytes=262144",
                             timeout=(3, 8), stream=True) as response:
                if response.status_code != 200:
                    return None
                start = time.monotonic()
                count = sum(len(chunk) for chunk in response.iter_content(32768))
                seconds = time.monotonic() - start
            if count != 262144 or seconds <= 0:
                return None
            mbps = count * 8 / seconds / 1_000_000
            return round(mbps, 2) if mbps >= MIN_MBPS else None
        except (requests.RequestException, OSError):
            return None
        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def country_labels(uris):
    """GeoIP for endpoint IPv4; hostname or lookup failure uses ZZ."""
    result = {}
    try:
        from update import GEOIP_URL
        response = requests.get(GEOIP_URL, timeout=(8, 20))
        response.raise_for_status()
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "Country.mmdb"
            db.write_bytes(response.content)
            with geoip2.database.Reader(str(db)) as reader:
                for uri in uris:
                    host = urlsplit(uri).hostname
                    code = "ZZ"
                    if host:
                        try:
                            code = reader.country(host).country.iso_code or "ZZ"
                        except (geoip2.errors.AddressNotFoundError, ValueError):
                            pass
                    result[uri] = (code.upper(), host or "unknown")
    except (requests.RequestException, OSError, ValueError, geoip2.errors.GeoIP2Error) as exc:
        print("GeoIP unavailable:", type(exc).__name__)
    for uri in uris:
        result.setdefault(uri, ("ZZ", urlsplit(uri).hostname or "unknown"))
    return result


def main():
    OUT.mkdir(exist_ok=True)
    stats = {"checked_at": datetime.now(timezone.utc).isoformat(),
             "verification": "sing-box HTTPS 204 and throughput"}
    names = {"vless_reality": "vless.txt"}
    for kind, filename in names.items():
        uris, success = collect(kind)
        checked = uris[:MAX_CHECKS]
        verified = []
        for uri in checked:
            speed = verify(uri)
            if speed is not None:
                verified.append((uri, speed))
        verified.sort(key=lambda item: -item[1])
        stats[kind] = {"sources_reached": success, "candidates": len(uris),
                       "tested": len(checked), "published": len(verified),
                       "min_mbps": MIN_MBPS, "max_latency_ms": MAX_LATENCY_MS}
        if success:
            labels = country_labels([uri for uri, _ in verified])
            lines = [f"{uri}#{quote(' '.join(labels[uri]), safe='')}"
                     for uri, speed in verified]
            (OUT / filename).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        else:
            print(f"{kind}: keeping last published file")
    # Combined file uses the latest published protocol lists, even if one upstream failed.
    combined = []
    for filename in ("proxies.txt", "vless.txt"):
        path = OUT / filename
        if path.exists():
            combined.extend(line for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    (OUT / "all.txt").write_text("\n".join(combined) + ("\n" if combined else ""), encoding="utf-8")
    (OUT / "protocol_status.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    print("Protocol collection:", {k: stats[k]["published"] for k in names})


if __name__ == "__main__":
    main()
