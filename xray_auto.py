"""AUTO plus every verified individual VLESS profile in measured-speed order."""
from copy import deepcopy

from incy import base_profile, profile
from vless import canonical, outbound

AUTO_LIMIT = 24  # Only active client probes are capped; individual choices are not.


def with_socks_fallback(automatic, socks_profiles):
    if not socks_profiles:
        return automatic

    result = deepcopy(automatic)
    socks = []
    for index, profile_config in enumerate(socks_profiles[:AUTO_LIMIT], 1):
        outbound_config = deepcopy(profile_config['outbounds'][0])
        outbound_config['tag'] = f'SOCKS5_{index:04d}'
        socks.append(outbound_config)

    result['remarks'] = 'AUTO | VLESS + SOCKS5'
    result['outbounds'].extend(socks)
    routing = result['routing']
    if not routing['balancers']:
        for rule in routing['rules']:
            if rule.get('outboundTag') == 'block':
                del rule['outboundTag']
                rule['balancerTag'] = 'AUTO'
        routing['balancers'] = [{'tag': 'AUTO', 'selector': [],
                                'strategy': {'type': 'leastLoad', 'settings': {'expected': 1}}}]
    balancer = routing['balancers'][0]
    balancer['selector'].append('SOCKS5_')
    balancer['fallbackTag'] = socks[0]['tag']
    result.setdefault('burstObservatory', {'subjectSelector': [], 'pingConfig': {
        'destination': 'https://www.gstatic.com/generate_204', 'connectivity': '',
        'interval': '30s', 'sampling': 2, 'timeout': '8s'}})
    result['burstObservatory']['subjectSelector'].append('SOCKS5_')
    return result


def build_auto(uris):
    uris = list(dict.fromkeys(canonical(u) for u in uris))
    remotes = [outbound(u, f'VLESS_{i:04d}') for i, u in enumerate(uris[:AUTO_LIMIT], 1)]
    target = {'balancerTag': 'AUTO'} if remotes else {'outboundTag': 'block'}
    result = base_profile(remotes, target)
    result['remarks'] = 'AUTO VLESS | XHTTP + TCP REALITY'
    # Block by default if a client loses routing; a manual profile defaults to its sole proxy.
    block = next(o for o in result['outbounds'] if o['tag'] == 'block')
    result['outbounds'].remove(block)
    result['outbounds'].insert(0, block)
    if remotes:
        result['routing']['balancers'] = [{'tag': 'AUTO', 'selector': ['VLESS_'],
            'fallbackTag': 'block', 'strategy': {'type': 'leastLoad', 'settings': {'expected': 1}}}]
        result['burstObservatory'] = {'subjectSelector': ['VLESS_'], 'pingConfig': {
            'destination': 'https://www.gstatic.com/generate_204', 'connectivity': '',
            'interval': '30s', 'sampling': 2, 'timeout': '8s'}}
    return result


def build_choices(uris, names=None):
    uris = list(dict.fromkeys(canonical(u) for u in uris))
    names = names or {}
    return [build_auto(uris)] + [profile(u, names.get(u, 'VLESS')) for u in uris]
