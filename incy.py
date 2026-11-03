"""Full client profiles; verification changes only local listen ports and labels."""
from copy import deepcopy
import hashlib
import ipaddress
import json

from vless import canonical, outbound

RU_DOMAINS = [r'regexp:(?i)(^|\.)(ru|su|xn--p1ai)$', 'domain:yandex.com',
              'domain:yandex.net', 'domain:vk.com', 'domain:ok.ru',
              'domain:ozon.ru', 'domain:wildberries.ru']
PRIVATE_IPS = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
               '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10']


def base_profile(remotes, target):
    bootstrap = []
    for remote in remotes:
        host = remote['settings']['vnext'][0]['address']
        try:
            ipaddress.ip_address(host)
        except ValueError:
            bootstrap.append('full:' + host)
    sniff = {'enabled': True, 'routeOnly': True, 'destOverride': ['http', 'tls', 'quic']}
    return {
        'remarks': 'VLESS', 'log': {'loglevel': 'warning'},
        'dns': {'tag': 'dns-query', 'queryStrategy': 'UseIPv4',
                'hosts': {'cloudflare-dns.com': '1.1.1.1'},
                'servers': [{'address': '8.8.8.8', 'domains': RU_DOMAINS + sorted(set(bootstrap)),
                             'skipFallback': True}, 'https://cloudflare-dns.com/dns-query']},
        'inbounds': [
            {'tag': 'socks-in', 'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
             'settings': {'auth': 'noauth', 'udp': True}, 'sniffing': deepcopy(sniff)},
            {'tag': 'http-in', 'listen': '127.0.0.1', 'port': 10809, 'protocol': 'http',
             'settings': {}, 'sniffing': deepcopy(sniff)}],
        'outbounds': deepcopy(remotes) + [
            {'tag': 'block', 'protocol': 'blackhole'},
            {'tag': 'direct', 'protocol': 'freedom', 'settings': {},
             'streamSettings': {'sockopt': {'domainStrategy': 'UseIPv4'}}},
            {'tag': 'dns-out', 'protocol': 'dns', 'settings': {}},
            {'tag': 'fragment', 'protocol': 'freedom', 'settings': {
                'fragment': {'packets': 'tlshello', 'length': '100-200', 'interval': '0-1'}},
             'streamSettings': {'sockopt': {'domainStrategy': 'UseIPv4'}}}],
        'routing': {'domainStrategy': 'AsIs', 'balancers': [], 'rules': [
            {'type': 'field', 'inboundTag': ['dns-query'], 'ip': ['8.8.8.8'],
             'port': '53', 'outboundTag': 'direct'},
            {'type': 'field', 'inboundTag': ['dns-query'], **target},
            {'type': 'field', 'port': '53', 'network': 'tcp,udp', 'outboundTag': 'dns-out'},
            {'type': 'field', 'domain': ['dotless:', 'domain:local', 'domain:localdomain'], 'outboundTag': 'direct'},
            {'type': 'field', 'ip': PRIVATE_IPS, 'outboundTag': 'direct'},
            {'type': 'field', 'domain': RU_DOMAINS, 'outboundTag': 'direct'},
            {'type': 'field', 'network': 'tcp,udp', **target}]} }


def profile(uri, name='VLESS'):
    result = base_profile([outbound(uri)], {'outboundTag': 'proxy'})
    result['remarks'] = name
    return result


def connection_digest(config):
    config = deepcopy(config)
    config.pop('remarks', None)
    for inbound in config['inbounds']:
        inbound['port'] = 10808 if inbound['tag'] == 'socks-in' else 10809
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def build_subscription(uris):
    seen, result = set(), []
    for uri in uris:
        core = canonical(uri)
        if core not in seen:
            seen.add(core)
            result.append(profile(core))
    return result
