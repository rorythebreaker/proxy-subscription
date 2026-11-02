"""Export verified share URIs as full, independent Xray profiles for INCY."""
from collections import Counter
from urllib.parse import unquote, urlsplit

from subscription import canonical_socks
from update_protocols import Unsupported, as_outbound, parse_reality

DNS_SERVERS = ['8.8.8.8', '1.1.1.1']


def proxy_outbound(uri, tag):
    """Convert only semantics that the INCY Xray engine can faithfully reproduce."""
    if urlsplit(uri).scheme in ('socks', 'socks5'):
        p = urlsplit(canonical_socks(uri))
        return {'tag': tag, 'protocol': 'socks',
                'settings': {'servers': [{'address': p.hostname, 'port': p.port}]}}
    # Share the existing allowlist and validation with the connectivity verifier.
    as_outbound(uri)
    _, p, q = parse_reality(uri)
    network = q.get('type', 'tcp') or 'tcp'
    if network == 'raw':
        network = 'tcp'
    if network not in ('tcp', 'grpc'):
        # Xray REALITY supports RAW/XHTTP/gRPC, unlike sing-box's TLS wrapper.
        # XHTTP is not yet checked by our collector; never substitute another transport.
        raise Unsupported('xray_reality_transport')
    if q.get('alpn'):
        # Xray REALITY derives ALPN from the fingerprint; it exposes no ALPN override.
        raise Unsupported('xray_reality_alpn')
    user = {'id': p.username, 'encryption': 'none'}
    if q.get('flow'):
        user['flow'] = q['flow']
    stream = {'network': network, 'security': 'reality',
              'realitySettings': {'serverName': q['sni'], 'fingerprint': q['fp'],
                                  'publicKey': q['pbk'], 'shortId': q.get('sid', ''),
                                  'spiderX': q.get('spx', '/')},
              'sockopt': {'domainStrategy': 'UseIPv4'}}
    if network == 'grpc':
        stream['grpcSettings'] = {'serviceName': q.get('serviceName', ''), 'multiMode': False}
    return {'tag': tag, 'protocol': 'vless',
            'settings': {'vnext': [{'address': p.hostname, 'port': p.port, 'users': [user]}]},
            'streamSettings': stream}


def profile(uri):
    p = urlsplit(uri)
    protocol = 'SOCKS5' if p.scheme in ('socks', 'socks5') else 'VLESS'
    label = unquote(p.fragment) if p.fragment else f'ZZ {p.hostname}'
    name = f'{protocol} {label}'
    proxy = proxy_outbound(uri, name)
    sniffing = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': False}
    return {
        'remarks': name,
        'meta': {'serverDescription': 'DNS 8.8.8.8 / 1.1.1.1; IPv4'},
        'log': {'loglevel': 'warning'},
        'dns': {'servers': list(DNS_SERVERS), 'queryStrategy': 'UseIPv4', 'tag': 'dns-query'},
        'inbounds': [
            {'tag': 'socks-in', 'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
             'settings': {'auth': 'noauth', 'udp': True}, 'sniffing': dict(sniffing)},
            {'tag': 'http-in', 'listen': '127.0.0.1', 'port': 10809, 'protocol': 'http',
             'settings': {}, 'sniffing': dict(sniffing)},
        ],
        # First outbound is the default: all ordinary traffic uses the selected proxy.
        'outbounds': [proxy,
                      {'tag': 'direct', 'protocol': 'freedom', 'settings': {},
                       'streamSettings': {'sockopt': {'domainStrategy': 'UseIPv4'}}},
                      {'tag': 'dns-out', 'protocol': 'dns', 'settings': {}}],
        'routing': {'domainStrategy': 'AsIs', 'rules': [
            # Built-in DNS goes directly to these two explicit resolvers, avoiding loops.
            {'type': 'field', 'inboundTag': ['dns-query'], 'outboundTag': 'direct'},
            {'type': 'field', 'ip': [f'{ip}/32' for ip in DNS_SERVERS], 'port': '53',
             'network': 'tcp,udp', 'outboundTag': 'direct'},
            # Intercept conventional DNS entering the local proxy (e.g. from TUN).
            {'type': 'field', 'inboundTag': ['socks-in', 'http-in'], 'port': '53',
             'network': 'tcp,udp', 'outboundTag': 'dns-out'},
        ]},
    }


def build_subscription(uris):
    profiles, skipped, seen = [], Counter(), set()
    for uri in uris:
        try:
            core = parse_reality(uri)[0] if urlsplit(uri).scheme == 'vless' else canonical_socks(uri)
            if core in seen:
                continue
            seen.add(core)
            profiles.append(profile(uri))
        except Unsupported as exc:
            # Only fixed local categories go into public diagnostics, never credentials.
            reason = str(exc)
            skipped[reason if reason.startswith('xray_reality_') else 'unsupported_parameters'] += 1
        except (ValueError, TypeError, AttributeError):
            skipped['invalid_uri'] += 1
    return profiles, {'published': len(profiles), 'skipped': dict(skipped),
                      'dns_servers': list(DNS_SERVERS), 'dns_transport': 'udp', 'dns_route': 'direct'}
