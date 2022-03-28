import subprocess
import os
from config import *

template_nmp = """protocol bgp dn42_{}_v4 from dnpeers {{
    neighbor {} as {};
    direct;
    ipv6 {{
        import none;
        export none;
    }};
}};

protocol bgp dn42_{}_v6 from dnpeers {{
    neighbor {} % '{}' as {};
    direct;
    ipv4 {{
        import none;
        export none;
    }};
}};
"""
template_mp = '''protocol bgp dn42_{}_v6 from dnpeers {{
    neighbor {} % '{}' as {};
    direct;
}};
'''


def add_bird_peer_nmp(name, asn, ipv4, link_local):
    with open(os.path.join(BIRD_PEERS_BASE, 'dn42_' + name + '.conf'), 'w') as f:
        f.write(template_nmp.format(name, ipv4, asn, name, link_local, name, asn))
    subprocess.run(['birdc', 'con'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=WG_PEERS_BASE)


def add_bird_peer_mp(name, asn, link_local):
    with open(os.path.join(BIRD_PEERS_BASE, 'dn42_' + name + '.conf'), 'w') as f:
        f.write(template_mp.format(name, link_local, name, asn))
    subprocess.run(['birdc', 'con'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=WG_PEERS_BASE)
