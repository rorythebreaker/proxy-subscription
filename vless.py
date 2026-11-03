"""One strict URI-to-Xray mapping shared by collection, verification and export."""
import base64
import hashlib
import ipaddress
import json
import re
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit


class Unsupported(ValueError):
    pass


def _reject_constant(value):
    raise ValueError('non-finite JSON number')


def parse(uri):
    if not isinstance(uri, str) or len(uri) > 32768 or any(ord(c) < 32 for c in uri):
        raise ValueError('invalid URI')
    p = urlsplit(uri.strip())
    if p.scheme != 'vless' or not p.hostname or not p.port or p.password is not None or p.path not in ('', '/'):
        raise ValueError('invalid authority')
    try:
        user = str(uuid.UUID(p.username))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError('invalid UUID') from exc
    try:
        address = ipaddress.ip_address(p.hostname)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9-]{2,63}', p.hostname):
            raise ValueError('invalid hostname')
        if p.hostname.lower().endswith(('.localhost', '.local', '.internal')):
            raise ValueError('local endpoint')
    else:
        if not address.is_global:
            raise ValueError('non-public endpoint')
    pairs = parse_qsl(p.query, keep_blank_values=True, strict_parsing=True)
    q = dict(pairs)
    if len(q) != len(pairs):
        raise ValueError('duplicate parameters')
    q['security'] = q.get('security', '').lower()
    q['type'] = q.get('type') or 'tcp'
    if q['type'] == 'raw':
        q['type'] = 'tcp'
    pair = q['type'], q['security']
    if pair not in (('tcp', 'reality'), ('xhttp', 'tls')):
        raise Unsupported('excluded_transport')
    common = {'security', 'type', 'encryption', 'flow', 'sni', 'fp', 'headerType', 'allowInsecure', 'insecure'}
    allowed = common | ({'pbk', 'sid', 'spx'} if pair[1] == 'reality' else {'host', 'path', 'mode', 'extra', 'alpn'})
    if set(q) - allowed:
        raise Unsupported('unsupported_parameters')
    if q.get('encryption', 'none') not in ('', 'none'):
        raise Unsupported('unsupported_encryption')
    if q.get('headerType', 'none') not in ('', 'none'):
        raise Unsupported('unsupported_header')
    if any(q.get(k, '').lower() not in ('', '0', 'false') for k in ('allowInsecure', 'insecure')):
        raise Unsupported('insecure_tls')
    for key in ('allowInsecure', 'insecure', 'headerType'):
        q.pop(key, None)
    q['encryption'] = 'none'
    q['fp'] = q.get('fp') or 'chrome'
    if q['fp'] not in ('chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized'):
        raise Unsupported('unsupported_fingerprint')
    q['flow'] = q.get('flow') or ''
    if q['security'] == 'reality':
        if q['flow'] not in ('', 'xtls-rprx-vision'):
            raise Unsupported('unsupported_flow')
        key = q.get('pbk', '')
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', key) or len(base64.b64decode(key + '=', altchars=b'-_', validate=True)) != 32:
            raise ValueError('invalid public key')
        q['sid'] = q.get('sid', '').lower()
        if not re.fullmatch(r'(?:[0-9a-f]{2}){0,8}', q['sid']):
            raise ValueError('invalid short ID')
        q['spx'] = q.get('spx') or '/'
    else:
        if q['flow']:
            raise Unsupported('unsupported_flow')
        q['sni'] = q.get('sni') or p.hostname
        q['host'] = q.get('host') or ''
        q['path'] = q.get('path') or '/'
        q['mode'] = q.get('mode') or 'auto'
        if q['mode'] not in ('auto', 'packet-up', 'stream-up', 'stream-one'):
            raise Unsupported('unsupported_mode')
        if not q['path'].startswith('/') or any(ord(c) < 32 for c in q['host'] + q['path']):
            raise ValueError('invalid XHTTP path/host')
        if q.get('extra'):
            try:
                extra = json.loads(q['extra'], parse_constant=_reject_constant)
            except RecursionError as exc:
                raise ValueError('extra nesting too deep') from exc
            if not isinstance(extra, dict):
                raise ValueError('extra must be an object')
            q['extra'] = json.dumps(extra, sort_keys=True, separators=(',', ':'), allow_nan=False)
        else:
            q.pop('extra', None)
        if q.get('alpn') and any(x not in ('h2', 'http/1.1', 'h3') for x in q['alpn'].split(',')):
            raise Unsupported('unsupported_alpn')
    if not q.get('sni') or any(c.isspace() or c in '/?#@' or ord(c) < 32 for c in q['sni']):
        raise ValueError('invalid SNI')
    host = f'[{p.hostname}]' if ':' in p.hostname else p.hostname.lower()
    core = f'vless://{user}@{host}:{p.port}?{urlencode(sorted(q.items()))}'
    return core, p, q


def canonical(uri):
    return parse(uri)[0]


def transport(uri):
    return 'tcp_reality' if parse(uri)[2]['security'] == 'reality' else 'xhttp_tls'


def node_id(uri):
    return hashlib.sha256(canonical(uri).encode()).hexdigest()[:16]


def outbound(uri, tag='proxy'):
    _, p, q = parse(uri)
    user = {'id': str(uuid.UUID(p.username)), 'encryption': 'none'}
    if q['flow']:
        user['flow'] = q['flow']
    stream = {'network': q['type'], 'security': q['security'], 'sockopt': {'domainStrategy': 'UseIPv4'}}
    if q['security'] == 'reality':
        stream['realitySettings'] = {'serverName': q['sni'], 'publicKey': q['pbk'],
                                     'shortId': q['sid'], 'fingerprint': q['fp'], 'spiderX': q['spx']}
        # This dialer is also present in the exact profile used for verification.
        stream['sockopt']['dialerProxy'] = 'fragment'
    else:
        stream['tlsSettings'] = {'serverName': q['sni'], 'fingerprint': q['fp']}
        if q.get('alpn'):
            stream['tlsSettings']['alpn'] = q['alpn'].split(',')
        stream['xhttpSettings'] = {key: q[key] for key in ('host', 'path', 'mode')}
        if q.get('extra'):
            stream['xhttpSettings']['extra'] = json.loads(q['extra'])
    return {'tag': tag, 'protocol': 'vless', 'settings': {'vnext': [
        {'address': p.hostname, 'port': p.port, 'users': [user]}]}, 'streamSettings': stream}
