"""Bounded probes, persisted measurements and publication of current-run passes only."""
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import time
from urllib.parse import quote, urlsplit

OUT = Path(os.getenv('OUTPUT_DIR', 'public'))
TTL = 600
MIN_SPEED_MBPS = float(os.getenv('MIN_SPEED_MBPS', '10'))
MAX_LATENCY_MS = float(os.getenv('MAX_LATENCY_MS', '6000'))
SPEED_TEST_BYTES = 2 * 1024 * 1024
SPEED_TEST_SECONDS = 14
QUALITY_POLICY = f'xray-full-profile-v3:{MIN_SPEED_MBPS}:{MAX_LATENCY_MS}:{SPEED_TEST_BYTES}:two-samples'
TARGETS = ('https://www.gstatic.com/generate_204', 'https://cp.cloudflare.com/generate_204')


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def age(value):
    try:
        stamp = datetime.fromisoformat(value)
        if stamp.tzinfo is None:
            return float('inf')
        seconds = time.time() - stamp.timestamp()
        return float('inf') if seconds < -60 else max(0, seconds)
    except (ValueError, TypeError, OverflowError):
        return float('inf')


def load_json(path):
    try:
        value = json.loads(Path(path).read_text())
        return value if isinstance(value, dict) else {}
    except (ValueError, OSError):
        return {}


def atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(text, encoding='utf-8')
    temporary.replace(path)


def write_json(path, value):
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n')


def curl(args, seconds=10):
    return subprocess.run(['curl', '--disable', '--silent', '--show-error',
        '--max-time', str(seconds), '--connect-timeout', str(min(5, seconds)),
        '--proto', '=https', *args], capture_output=True, timeout=seconds + 1)


def fetch_bytes(url, max_bytes=16_000_000):
    result = curl(['--fail', '--location', '--proto-redir', '=https', '--proxy', '',
        '--noproxy', '*', '--max-filesize', str(max_bytes), url], 15)
    if result.returncode or len(result.stdout) > max_bytes:
        raise ValueError('source download failed')
    return result.stdout


def decode_lines(body):
    text = body.decode('utf-8-sig').strip()
    if not text:
        return []
    if not re.search(r'(?m)^\s*[a-zA-Z][\w+.-]*://', text):
        compact = re.sub(r'\s+', '', text)
        text = base64.b64decode(compact + '=' * (-len(compact) % 4), altchars=b'-_', validate=True).decode('utf-8')
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]


def probe(proxy, url):
    try:
        result = curl(['--proxy', proxy or '', '--noproxy', '' if proxy else '*',
                       '--output', os.devnull, '--write-out', '%{http_code} %{time_total}', url], 7)
        code, elapsed = result.stdout.decode().split()
        latency = float(elapsed) * 1000
        if result.returncode == 0 and code == '204' and math.isfinite(latency) and latency >= 0:
            return latency
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return None


def healthy_targets():
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda url: probe(None, url), TARGETS))
    return [url for url, result in zip(TARGETS, results) if result is not None]


def measure_speed(proxy=None):
    try:
        result = curl(['--proxy', proxy or '', '--noproxy', '' if proxy else '*',
            '--output', os.devnull, '--max-filesize', str(SPEED_TEST_BYTES),
            '--write-out', '%{http_code} %{size_download} %{time_total} %{time_starttransfer}',
            f'https://speed.cloudflare.com/__down?bytes={SPEED_TEST_BYTES}'], SPEED_TEST_SECONDS)
        code, size, total, first = result.stdout.decode().split()
        total, first = float(total), float(first)
        elapsed = total - first
        # A partial timeout is never a successful speed qualification.
        if result.returncode != 0 or code != '200' or int(size) != SPEED_TEST_BYTES:
            return None
        if not all(math.isfinite(v) for v in (total, first, elapsed)) or first < 0 or elapsed <= 0:
            return None
        return SPEED_TEST_BYTES * 8 / elapsed / 1_000_000
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def quality(proxy, deadline, slots):
    samples = []
    # Two qualifying downloads are required, with one extra attempt for a transient failure.
    for _ in range(3):
        remaining = deadline - time.monotonic() - SPEED_TEST_SECONDS - 1
        if remaining <= 0 or not slots.acquire(timeout=max(0, remaining)):
            return {'status': 'not_tested', 'speed_samples_mbps': samples}
        try:
            if time.monotonic() + SPEED_TEST_SECONDS + 1 >= deadline:
                return {'status': 'not_tested', 'speed_samples_mbps': samples}
            speed = measure_speed(proxy)
        finally:
            slots.release()
        if speed is not None and math.isfinite(speed) and speed > 0:
            samples.append(speed)
        good = [v for v in samples if v >= MIN_SPEED_MBPS]
        if len(good) >= 2:
            return {'status': 'passed', 'speed_mbps': min(good), 'speed_samples_mbps': samples}
        if len([v for v in samples if v < MIN_SPEED_MBPS]) >= 2:
            return {'status': 'speed_rejected', 'speed_samples_mbps': samples}
    return {'status': 'speed_unconfirmed', 'speed_samples_mbps': samples}


def read_exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise OSError('unexpected EOF')
        data += part
    return data


def check_dns(port):
    """Exercise the profile's DNS interception and built-in DoH through its proxy."""
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=6) as sock:
            sock.settimeout(6)
            sock.sendall(b'\x05\x01\x00')
            if read_exact(sock, 2) != b'\x05\x00':
                return False
            sock.sendall(b'\x05\x01\x00\x01\x01\x01\x01\x01\x00\x35')
            version, status, _, kind = read_exact(sock, 4)
            if version != 5 or status != 0:
                return False
            lengths = {1: 4, 4: 16}
            length = read_exact(sock, 1)[0] if kind == 3 else lengths.get(kind)
            if length is None:
                return False
            read_exact(sock, length + 2)
            txid = os.urandom(2)
            question = b''.join(bytes([len(s)]) + s.encode() for s in 'www.gstatic.com'.split('.')) + b'\x00\x00\x01\x00\x01'
            query = txid + struct.pack('!5H', 0x0100, 1, 0, 0, 0) + question
            sock.sendall(struct.pack('!H', len(query)) + query)
            size = struct.unpack('!H', read_exact(sock, 2))[0]
            if size < 12 or size > 16384:
                return False
            response = read_exact(sock, size)
            flags, _, answers = struct.unpack('!3H', response[2:8])
            return response[:2] == txid and bool(flags & 0x8000) and not flags & 0x020F and answers > 0
    except (OSError, ValueError, struct.error):
        return False


def valid_record(uri, record):
    from incy import profile, connection_digest
    try:
        if not isinstance(record, dict) or record.get('quality_policy') != QUALITY_POLICY:
            return False
        speed, latency = record['speed_mbps'], record['latency_ms']
        samples = record['speed_samples_mbps']
        good = [v for v in samples if isinstance(v, (int, float)) and math.isfinite(v) and v >= MIN_SPEED_MBPS]
        return (record.get('status') == 'passed' and age(record['checked_at']) <= TTL
                and isinstance(speed, (int, float)) and math.isfinite(speed) and speed >= MIN_SPEED_MBPS
                and len(good) >= 2 and speed == min(good)
                and isinstance(latency, (int, float)) and math.isfinite(latency) and 0 <= latency <= MAX_LATENCY_MS
                and record.get('https_targets') == list(TARGETS) and record.get('dns_ok') is True
                and record.get('config_digest') == connection_digest(profile(uri)))
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False


def publish(records, details):
    """Every call replaces the complete publication; failed/untested cache never survives."""
    from incy import profile
    from vless import canonical, node_id, transport
    from xray_auto import build_auto
    nodes = {}
    for record in records:
        try:
            uri = canonical(record['uri'])
            if valid_record(uri, record):
                old = nodes.get(uri)
                if old is None or record['speed_mbps'] > old['speed_mbps']:
                    nodes[uri] = record
        except (ValueError, TypeError, KeyError):
            continue
    ranked = sorted(nodes, key=lambda u: (-nodes[u]['speed_mbps'], nodes[u]['latency_ms'], node_id(u)))
    names, summary = {}, []
    for rank, uri in enumerate(ranked, 1):
        data, p = nodes[uri], urlsplit(uri)
        kind = transport(uri)
        label = 'XHTTP TLS' if kind == 'xhttp_tls' else 'TCP REALITY'
        names[uri] = f'{rank:04d} | {data["speed_mbps"]:.1f} Mbps | {label} | {p.netloc.split("@", 1)[1]}'
        summary.append({'rank': rank, 'id': node_id(uri), 'address': p.hostname, 'port': p.port,
            'transport': kind, 'speed_mbps': data['speed_mbps'], 'latency_ms': data['latency_ms'],
            'checked_at': data['checked_at'], 'sources': data.get('sources', [])})
    profiles = [profile(uri, names[uri]) for uri in ranked]
    auto = build_auto(ranked)
    text = '\n'.join(f'{uri}#{quote(names[uri], safe="")}' for uri in ranked)
    for filename in ('vless.txt', 'all.txt'):
        atomic_write(OUT / filename, text + ('\n' if text else ''))
    write_json(OUT / 'incy.json', profiles)
    write_json(OUT / 'xray-auto.json', [auto] + profiles)
    write_json(OUT / 'xray-auto-only.json', auto)
    write_json(OUT / 'servers.json', summary)
    write_json(OUT / 'vless_state.json', {'nodes': {u: nodes[u] for u in ranked}})
    counts = dict(Counter(item['transport'] for item in summary))
    status = {**details, 'published_at': timestamp(), 'published': len(ranked), 'counts': counts,
              'quality_policy': QUALITY_POLICY, 'min_speed_mbps': MIN_SPEED_MBPS,
              'max_latency_ms': MAX_LATENCY_MS, 'sort': 'speed_mbps descending, latency_ms ascending',
              'verification': 'full Xray client profile: two HTTPS targets, DNS, two full speed samples',
              'auto_nodes': min(len(ranked), 24), 'individual_profiles': len(ranked)}
    for filename in ('status.json', 'protocol_status.json', 'combined_status.json'):
        write_json(OUT / filename, status)
    # Empty legacy lists clear old SOCKS subscriptions instead of continuing to serve stale nodes.
    for filename in ('proxies.txt', 'alive.txt'):
        atomic_write(OUT / filename, '')
    for filename in ('socks_state.json', 'shadowsocks.txt'):
        (OUT / filename).unlink(missing_ok=True)
    return status
