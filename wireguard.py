import subprocess
import os
from config import *

template = """[Interface]
PrivateKey = {}
ListenPort = {}
Table = off
PostUp = ip addr add {}/64 dev %i
PostUp = ip addr add {}/128 dev %i
PostUp = ip addr add {} peer {} dev %i
PostUp = sysctl -w net.ipv6.conf.%i.autoconf=0

[Peer]
PublicKey = {}
Endpoint = {}
AllowedIPs = 10.0.0.0/8, 172.20.0.0/14, 172.31.0.0/16, fd00::/8, fe80::/64
"""


def add_wg_peer(name, listening_port, remote_ipv4, publickey, endpoint):
    with open(os.path.join(WG_PEERS_BASE, name + '.conf'), 'w') as f:
        f.write(template.format(PRIVATE_KEY, listening_port, LOCAL_LINK_LOCAL, LOCAL_IPV6, LOCAL_IPV4, remote_ipv4, publickey, endpoint))
    subprocess.run(['wg-quick', 'down', name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=WG_PEERS_BASE)
    subprocess.run(['wg-quick', 'up', name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=WG_PEERS_BASE)


def del_wg_peer(name):
    subprocess.run(['wg-quick', 'down', name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=WG_PEERS_BASE)
    os.remove(os.path.join(WG_PEERS_BASE, name + '.conf'))
