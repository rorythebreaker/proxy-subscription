"""One portable Xray profile with locally observed VLESS/SOCKS failover."""
from copy import deepcopy
from ipaddress import ip_address

from incy import build_subscription

# Bound client probing cost; favour distinct endpoints over duplicate accounts.
LIMITS = {'vless': 24, 'socks': 8}
RU_DOMAINS = [
    r'regexp:(?i)(^|\.)(ru|su|xn--p1ai)$',
    'domain:yandex.com', 'domain:yandex.net', 'domain:vk.com',
    'domain:ok.ru', 'domain:ozon.ru', 'domain:wildberries.ru',
]
PRIVATE_IPS = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12',
               '192.168.0.0/16', '169.254.0.0/16', '::1/128',
               'fc00::/7', 'fe80::/10']


def build_auto(uris):
    profiles, diagnostics = build_subscription(uris)
    groups = {'vless': [], 'socks': []}
    seen = set()
    bootstrap = []
    for item in profiles:
        outbound = deepcopy(item['outbounds'][0])
        protocol = outbound['protocol']
        server = outbound['settings']['vnext' if protocol == 'vless' else 'servers'][0]
        endpoint = (protocol, server['address'], server['port'])
        if endpoint in seen or len(groups[protocol]) >= LIMITS[protocol]:
            continue
        seen.add(endpoint)
        try:
            ip_address(server['address'])
        except ValueError:
            bootstrap.append('full:' + server['address'])
        prefix = 'VLESS_' if protocol == 'vless' else 'SOCKS_'
        outbound['tag'] = prefix + str(len(groups[protocol]) + 1).zfill(3)
        if protocol == 'vless':
            outbound['streamSettings']['sockopt']['dialerProxy'] = 'fragment'
        groups[protocol].append(outbound)

    # Block is the default if a client drops the catch-all balancer rule.
    outbounds = [{'tag': 'block', 'protocol': 'blackhole'}]
    outbounds += groups['vless'] + groups['socks']
    outbounds += [
        {'tag': 'direct', 'protocol': 'freedom', 'settings': {},
         'streamSettings': {'sockopt': {'domainStrategy': 'UseIPv4'}}},
        {'tag': 'dns-out', 'protocol': 'dns', 'settings': {}},
        {'tag': 'fragment', 'protocol': 'freedom', 'settings': {
            # Retain this format for Happ 26.10.21 / INCY 26.10.20 compatibility.
            'fragment': {'packets': 'tlshello', 'length': '100-200', 'interval': '0-1'}},
         'streamSettings': {'sockopt': {'domainStrategy': 'UseIPv4'}}},
    ]
    balancers = []
    if groups['socks']:
        balancers.append({'tag': 'SOCKS', 'selector': ['SOCKS_'], 'fallbackTag': 'block',
                          'strategy': {'type': 'leastLoad', 'settings': {'expected': 1}}})
    fallback = 'block'
    if groups['vless'] and groups['socks']:
        fallback = 'socks-fallback'
        outbounds.append({'tag': fallback, 'protocol': 'loopback',
                          'settings': {'inboundTag': 'socks-fallback-in'}})
    if groups['vless']:
        balancers.append({'tag': 'AUTO', 'selector': ['VLESS_'], 'fallbackTag': fallback,
                          'strategy': {'type': 'leastLoad', 'settings': {'expected': 1}}})
    target = ({'balancerTag': 'AUTO'} if groups['vless'] else
              {'balancerTag': 'SOCKS'} if groups['socks'] else {'outboundTag': 'block'})
    rules = []
    if fallback != 'block':
        rules.append({'type': 'field', 'inboundTag': ['socks-fallback-in'], 'balancerTag': 'SOCKS'})
    rules += [
        # UDP bootstrap DNS must not depend on the tunnel it helps establish.
        {'type': 'field', 'inboundTag': ['dns-query'], 'ip': ['8.8.8.8', '1.1.1.1'],
         'port': '53', 'outboundTag': 'direct'},
        {'type': 'field', 'inboundTag': ['dns-query'], **target},
        # Also covers the TUN inbound added by the client.
        {'type': 'field', 'port': '53', 'network': 'tcp,udp', 'outboundTag': 'dns-out'},
        {'type': 'field', 'domain': ['dotless:', 'domain:local', 'domain:localdomain'],
         'outboundTag': 'direct'},
        {'type': 'field', 'ip': list(PRIVATE_IPS), 'outboundTag': 'direct'},
        {'type': 'field', 'domain': list(RU_DOMAINS), 'outboundTag': 'direct'},
        {'type': 'field', 'network': 'tcp,udp', **target},
    ]
    sniff = {'enabled': True, 'routeOnly': True, 'destOverride': ['http', 'tls', 'quic']}
    result = {
        'remarks': 'AUTO VLESS + SOCKS5',
        'log': {'loglevel': 'warning'},
        'dns': {'tag': 'dns-query', 'queryStrategy': 'UseIPv4',
                'hosts': {'cloudflare-dns.com': '1.1.1.1'},
                'servers': [
                    {'address': '8.8.8.8', 'domains': list(RU_DOMAINS) + bootstrap, 'skipFallback': True},
                    'https://cloudflare-dns.com/dns-query']},
        'inbounds': [
            {'tag': 'socks-in', 'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
             'settings': {'auth': 'noauth', 'udp': True}, 'sniffing': deepcopy(sniff)},
            {'tag': 'http-in', 'listen': '127.0.0.1', 'port': 10809, 'protocol': 'http',
             'settings': {}, 'sniffing': deepcopy(sniff)},
        ],
        'outbounds': outbounds,
        'routing': {'domainStrategy': 'AsIs', 'rules': rules, 'balancers': balancers},
    }
    selectors = (['VLESS_'] if groups['vless'] else []) + (['SOCKS_'] if groups['socks'] else [])
    if selectors:
        result['burstObservatory'] = {
            'subjectSelector': selectors,
            'pingConfig': {'destination': 'https://www.gstatic.com/generate_204',
                           'connectivity': '', 'interval': '30s', 'sampling': 2, 'timeout': '5s'}}
    return result, {'nodes': {p: len(g) for p, g in groups.items()},
                    'skipped': diagnostics['skipped'], 'limits': dict(LIMITS)}


def build_choices(uris):
    """Expose AUTO and every compatible node as independently selectable profiles."""
    uris = list(uris)
    auto, _ = build_auto(uris)
    profiles, _ = build_subscription(uris)
    choices = [auto]
    # build_subscription preserves input order but may omit incompatible/duplicate URIs.
    # Use each already validated outbound so manual choices are never capped by AUTO.
    for profile in profiles:
        outbound = deepcopy(profile['outbounds'][0])
        config = deepcopy(auto)
        config['remarks'] = profile['remarks']
        outbound['tag'] = 'selected-proxy'
        if outbound['protocol'] == 'vless':
            outbound['streamSettings']['sockopt']['dialerProxy'] = 'fragment'
        config['outbounds'] = [outbound] + [deepcopy(o) for o in auto['outbounds']
            if o['tag'] in ('block', 'direct', 'dns-out', 'fragment')]
        config.pop('burstObservatory', None)
        config['routing']['balancers'] = []
        rules = []
        for rule in config['routing']['rules']:
            if rule.get('inboundTag') == ['socks-fallback-in']:
                continue
            if 'balancerTag' in rule:
                rule.pop('balancerTag')
                rule['outboundTag'] = 'selected-proxy'
            rules.append(rule)
        config['routing']['rules'] = rules
        # Bootstrap every manually selectable hostname, including those beyond AUTO's cap.
        server = outbound['settings']['vnext' if outbound['protocol'] == 'vless' else 'servers'][0]
        try:
            ip_address(server['address'])
        except ValueError:
            config['dns']['servers'][0]['domains'].append('full:' + server['address'])
        choices.append(config)
    return choices
