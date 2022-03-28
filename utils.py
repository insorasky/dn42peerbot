from config import *
import subprocess
from hashlib import md5
import time
import base64


class InvalidASNorIP(Exception):
    pass


def get_maintainer(asn_or_ip):
    data = subprocess.check_output(['whois', '-h', WHOIS_SERVER, asn_or_ip]).decode().strip()
    if data.endswith('% 404') or data.endswith('% This is the dn42 whois query service.'):
        raise InvalidASNorIP()
    mnt = [line.split('\n') for line in data.split('\n') if line.startswith('mnt-by:')][-1][0].strip().split(' ')[-1]
    asn = \
    [line.split('\n') for line in data.split('\n') if line.startswith('aut-num:') or line.startswith('origin:')][-1][
        0].strip().split(' ')[-1]
    return asn, mnt


def get_gpg_key(mntner):
    data = subprocess.check_output(['whois', '-h', WHOIS_SERVER, mntner]).decode().strip()
    if data[-5:] == '% 404':
        raise InvalidASNorIP()
    gpg_key = \
    [line.split('\n') for line in data.split('\n') if line.startswith('auth:               pgp-fingerprint')][-1][
        0].strip().split(' ')[-1]
    return gpg_key


def get_key(arg):
    info, hash_str = arg.split(':')
    timestamp, asn = base64.b64decode(info).decode().split(':')
    data = f"{HASH_KEY};{asn};{arg};{get_maintainer(asn)};"
    return md5(data.encode()).hexdigest()


def check_asn(asn, arg, key):
    info, hash_str = arg.split(':')
    timestamp, asn2 = base64.b64decode(info).decode().split(':')
    if asn != asn2:  # ASN和参数中的ASN不一致
        return False
    timestamp = int(timestamp)
    current_time = time.time() * 1000
    if current_time - timestamp > 15 * 60 * 1000:  # 参数过期
        return False
    if key != get_key(arg):  # 密钥不匹配
        return False
    return True


def get_arg(asn):
    current_time = int(time.time() * 1000)
    data = f'{current_time}:{asn}'
    return base64.b64encode(data.encode()).decode() + ':' + md5((data + ':' + HASH_KEY).encode()).hexdigest()


def ip2int(x):
    return sum([256 ** j * int(i) for j, i in enumerate(x.split('.')[::-1])])
