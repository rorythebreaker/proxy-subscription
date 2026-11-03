#!/usr/bin/env python3
"""Collect supported VLESS links and test the exact exported profile through Xray."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
from itertools import zip_longest
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

import subscription as common
from incy import profile, connection_digest
from vless import Unsupported, canonical, transport

MAX_ITEMS = int(os.getenv('MAX_PROTOCOL_NODES', '3000'))
MAX_CHECKS = int(os.getenv('MAX_PROTOCOL_CHECKS', '600'))
WORKERS = int(os.getenv('PROTOCOL_WORKERS', '24'))
CHECK_SECONDS = int(os.getenv('CHECK_SECONDS', '240'))
SPEED_WORKERS = int(os.getenv('SPEED_WORKERS', '4'))


def source_list():
    value = json.loads(Path(__file__).with_name('sources.json').read_text())
    if not isinstance(value, list) or not value:
        raise ValueError('empty source manifest')
    return value


def fetch_source(source):
    report = {'id': source['id'], 'url': source['url'], 'status': 'error', 'accepted': 0}
    try:
        body = common.fetch_bytes(source['url'])
        lines = common.decode_lines(body)
        if lines and not any('://' in line for line in lines):
            raise ValueError('unrecognized source')
        valid, rejected = {}, Counter()
        for line in lines:
            if not line.startswith('vless://'):
                rejected['other_protocol'] += 1
                continue
            try:
                uri = canonical(line)
                valid[uri] = {'uri': uri, 'transport': transport(uri), 'sources': [source['id']]}
            except Unsupported as exc:
                rejected[str(exc)] += 1
            except (ValueError, TypeError, AttributeError):
                rejected['invalid'] += 1
        report.update(status='ok', bytes=len(body), accepted=len(valid), rejected=dict(rejected))
        return list(valid.values()), report
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return [], report


def interleave(items):
    xhttp = [n for n in items if n['transport'] == 'xhttp_tls']
    reality = [n for n in items if n['transport'] == 'tcp_reality']
    return [n for pair in zip_longest(xhttp, reality) for n in pair if n]


def collect(sources=None, epoch=None):
    sources = source_list() if sources is None else sources
    epoch = int(time.time() // 300) if epoch is None else epoch
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(sources)))) as pool:
        fetched = list(pool.map(fetch_source, sources))
    all_nodes = {}
    lists = []
    for items, report in fetched:
        # Rotate before the global cap, so tails of large sources are eventually checked.
        items.sort(key=lambda n: hashlib.sha256(f'{epoch}:{n["uri"]}'.encode()).digest())
        lists.append(iter(interleave(items)))
        for node in items:
            if node['uri'] in all_nodes:
                all_nodes[node['uri']]['sources'] = sorted(set(all_nodes[node['uri']]['sources'] + node['sources']))
            else:
                all_nodes[node['uri']] = deepcopy(node)
    selected = {}
    while lists and len(selected) < MAX_ITEMS:
        remaining = []
        for iterator in lists:
            try:
                node = next(iterator)
            except StopIteration:
                continue
            selected.setdefault(node['uri'], all_nodes[node['uri']])
            remaining.append(iterator)
            if len(selected) >= MAX_ITEMS:
                break
        lists = remaining
    return list(selected.values()), [report for _, report in fetched], len(all_nodes)


def candidates_with_history(candidates, history):
    chosen = {}
    if not isinstance(history, dict):
        history = {}
    valid = []
    for uri, data in history.items():
        try:
            core = canonical(uri)
            if not isinstance(data, dict):
                continue
            rate = data.get('speed_mbps', 0)
            if not isinstance(rate, (int, float)) or not 0 <= rate < float('inf'):
                rate = 0
            valid.append((core, data, rate))
        except (ValueError, TypeError):
            continue
    current = {n['uri']: n for n in candidates}
    for uri, data, rate in sorted(valid, key=lambda item: (-item[2], item[0])):
        chosen[uri] = current.get(uri, {'uri': uri, 'transport': transport(uri), 'sources': data.get('sources', [])})
    for node in interleave(candidates):
        chosen.setdefault(node['uri'], node)
    return list(chosen.values())[:MAX_CHECKS], len(chosen)


def verify(node, deadline, slots):
    record = dict(node, status='not_tested')
    if time.monotonic() + 35 >= deadline:
        return record
    process = None
    try:
        config = profile(node['uri'])
        digest = connection_digest(config)
        with tempfile.TemporaryDirectory(prefix='xray-check-') as folder:
            path = Path(folder) / 'profile.json'
            # Hold both allocations until the engine is ready to start.
            with socket.socket() as first, socket.socket() as second:
                first.bind(('127.0.0.1', 0))
                second.bind(('127.0.0.1', 0))
                port, http_port = first.getsockname()[1], second.getsockname()[1]
                config['inbounds'][0]['port'], config['inbounds'][1]['port'] = port, http_port
                path.write_text(json.dumps(config))
                check = subprocess.run(['xray', 'run', '-test', '-config', str(path)], capture_output=True, timeout=5)
                if check.returncode:
                    return dict(record, status='config_error')
            process = subprocess.Popen(['xray', 'run', '-config', str(path)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(40):
                if process.poll() is not None:
                    return dict(record, status='startup_failed')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                return dict(record, status='startup_failed')
            proxy = f'socks5h://127.0.0.1:{port}'
            latencies = []
            for target in common.TARGETS:
                passed = None
                for _ in range(2):
                    if time.monotonic() + 8 >= deadline:
                        return record
                    latency = common.probe(proxy, target)
                    if latency is not None and latency <= common.MAX_LATENCY_MS:
                        passed = latency
                        break
                if passed is None:
                    return dict(record, status='https_failed')
                latencies.append(passed)
            dns_ok = False
            for _ in range(2):
                if time.monotonic() + 8 >= deadline:
                    return record
                if common.check_dns(port):
                    dns_ok = True
                    break
            if not dns_ok:
                return dict(record, status='dns_failed')
            measured = common.quality(proxy, deadline, slots)
            record.update(measured)
            if measured['status'] != 'passed':
                return record
            if time.monotonic() + 8 >= deadline:
                return dict(record, status='not_tested')
            final = common.probe(proxy, common.TARGETS[0])
            if final is None or final > common.MAX_LATENCY_MS:
                return dict(record, status='postcheck_failed')
            return dict(record, checked_at=common.timestamp(), quality_policy=common.QUALITY_POLICY,
                        config_digest=digest, latency_ms=max([final, *latencies]),
                        https_targets=list(common.TARGETS), dns_ok=True)
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return dict(record, status='verification_error')
    finally:
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            except ProcessLookupError:
                process.wait()


def main():
    started = common.timestamp()
    deadline = time.monotonic() + CHECK_SECONDS
    details = {'started_at': started, 'error': None, 'strict_current_run': True}
    if not shutil.which('xray'):
        common.publish([], dict(details, error='xray_missing'))
        return
    candidates, reports, total = collect()
    history = common.load_json(common.OUT / 'vless_state.json').get('nodes', {})
    current_uris = {node['uri'] for node in candidates}
    history = {uri: data for uri, data in history.items() if uri in current_uris} if isinstance(history, dict) else {}
    chosen, available = candidates_with_history(candidates, history)
    details.update(sources=reports, discovered_supported=total, candidates=len(candidates),
                   selected=len(chosen), unselected=max(0, available - len(chosen)))
    skip_preflight = os.getenv('LOCAL_SKIP_PREFLIGHT') == '1'
    details['preflight_skipped'] = skip_preflight
    baseline = None
    if not skip_preflight:
        healthy = common.healthy_targets()
        baseline = common.measure_speed() if len(healthy) == 2 else None
        if len(healthy) != 2 or baseline is None or baseline < common.MIN_SPEED_MBPS * 4:
            common.publish([], dict(details, error='test_infrastructure_unhealthy', healthy_targets=len(healthy), baseline_mbps=baseline))
            return
    if not chosen and not any(s['status'] == 'ok' for s in reports):
        common.publish([], dict(details, error='all_sources_unavailable'))
        return
    slots = threading.BoundedSemaphore(SPEED_WORKERS)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(lambda node: verify(node, deadline, slots), chosen))
    counts = dict(Counter(r['status'] for r in results))
    by_transport = {kind: dict(Counter(r['status'] for r in results if r['transport'] == kind))
                    for kind in ('tcp_reality', 'xhttp_tls')}
    speed_diagnostics = []
    for record in results:
        attempts = record.get('speed_attempts_mbps')
        if attempts is None:
            continue
        endpoint = urlsplit(record['uri'])
        speed_diagnostics.append({
            'address': endpoint.hostname,
            'port': endpoint.port,
            'transport': record['transport'],
            'status': record['status'],
            'attempts_mbps': attempts,
        })
    details.update(results=counts, results_by_transport=by_transport,
                   speed_diagnostics=speed_diagnostics,
                   baseline_mbps=baseline, tested=sum(r['status'] != 'not_tested' for r in results))
    status = common.publish(results, details)
    print(json.dumps({k: status[k] for k in ('published', 'counts', 'results', 'results_by_transport')}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
