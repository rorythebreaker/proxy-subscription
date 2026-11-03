"""Build a separate Happ SOCKS5 subscription from the current network."""
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import subprocess
import time
from urllib.parse import urlsplit

import subscription as common
from incy import base_profile

SOURCES = (
    'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt',
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
)


def candidates(data):
    for line in data.decode('utf-8', errors='replace').splitlines():
        line = line.strip()
        try:
            endpoint = urlsplit(line if '://' in line else 'socks5://' + line)
            if endpoint.scheme != 'socks5' or endpoint.username is not None:
                continue
            address = ipaddress.ip_address(endpoint.hostname)
            port = endpoint.port
            if address.is_global and not address.is_multicast and port:
                yield address, port
        except (ValueError, TypeError):
            continue


def check(endpoint):
    address, port = endpoint
    host = f'[{address}]' if address.version == 6 else str(address)
    proxy = f'socks5h://{host}:{port}'
    latencies = [common.probe(proxy, target) for target in common.TARGETS]
    if any(value is None or value > common.MAX_LATENCY_MS for value in latencies):
        return None
    speeds = []
    for _ in range(3):
        speed = common.measure_speed(proxy)
        if speed is not None and speed >= common.MIN_SPEED_MBPS:
            speeds.append(speed)
        if len(speeds) == 2:
            remote = {'tag': 'proxy', 'protocol': 'socks',
                      'settings': {'servers': [{'address': str(address), 'port': port}]}}
            profile = base_profile([], {'outboundTag': 'proxy'})
            profile['outbounds'].insert(0, remote)
            profile['remarks'] = f'SOCKS5 | {host}:{port}'
            return min(speeds), max(latencies), profile
    return None


def main():
    endpoints = {}
    for source in SOURCES:
        try:
            for endpoint in candidates(common.fetch_bytes(source)):
                endpoints.setdefault(endpoint, None)
        except (ValueError, OSError, subprocess.SubprocessError):
            print(f'Source unavailable: {source}', flush=True)
    # Rotate the batch so successive runs test different addresses.
    ordered = list(endpoints)
    if ordered:
        offset = (int(time.time()) // 300 * 200) % len(ordered)
        ordered = (ordered[offset:] + ordered[:offset])[:200]
    with ThreadPoolExecutor(max_workers=8) as pool:
        passed = [item for item in pool.map(check, ordered) if item is not None]
    passed.sort(key=lambda item: (-item[0], item[1]))
    common.write_json(common.OUT / 'happ-socks5.json', [item[2] for item in passed])
    print(f'SOCKS5: {len(passed)} passed out of {len(ordered)} tested.')


if __name__ == '__main__':
    main()
