"""Faithful VLESS XHTTP + TLS share-link mapping for Xray verification/export."""
import json
import uuid

from update_protocols import Unsupported, parse_vless


def proxy_outbound(uri, tag):
    _, p, q = parse_vless(uri)
    if q['security'] != 'tls' or q.get('type') != 'xhttp':
        raise Unsupported('expected XHTTP + TLS')
    known = {'security', 'type', 'encryption', 'flow', 'sni', 'fp', 'alpn',
             'host', 'path', 'mode', 'extra', 'headerType', 'allowInsecure', 'insecure'}
    if set(q) - known:
        raise Unsupported('unknown XHTTP connection parameters')
    if any(q.get(k, '').lower() not in ('', '0', 'false') for k in ('allowInsecure', 'insecure')):
        raise Unsupported('TLS certificate verification must remain enabled')
    if q.get('encryption', 'none') not in ('', 'none') or q.get('flow'):
        raise Unsupported('unsupported XHTTP encryption or flow')
    if q.get('headerType', 'none') not in ('', 'none'):
        raise Unsupported('unsupported XHTTP header type')
    mode = q.get('mode') or 'auto'
    if mode not in ('auto', 'packet-up', 'stream-up', 'stream-one'):
        raise Unsupported('unsupported XHTTP mode')
    if q['fp'] not in ('chrome', 'firefox', 'edge', 'safari', '360', 'qq',
                       'ios', 'android', 'random', 'randomized'):
        raise Unsupported('unsupported TLS fingerprint')
    path = q.get('path') or '/'
    host = q.get('host', '')
    if not path.startswith('/') or any(c in host + path for c in '\r\n\x00'):
        raise ValueError('invalid XHTTP host/path')
    settings = {'host': host, 'path': path, 'mode': mode}
    if q.get('extra'):
        extra = json.loads(q['extra'])
        if not isinstance(extra, dict):
            raise ValueError('XHTTP extra must be an object')
        settings['extra'] = extra
    tls = {'serverName': q['sni'], 'fingerprint': q['fp']}
    if q.get('alpn'):
        tls['alpn'] = q['alpn'].split(',')
    return {'tag': tag, 'protocol': 'vless',
            'settings': {'vnext': [{'address': p.hostname, 'port': p.port,
                                   'users': [{'id': str(uuid.UUID(p.username)),
                                              'encryption': 'none'}]}]},
            'streamSettings': {'network': 'xhttp', 'security': 'tls',
                               'tlsSettings': tls, 'xhttpSettings': settings,
                               'sockopt': {'domainStrategy': 'UseIPv4'}}}
