from src.enums import ProtocolType, IPVersion
import re


def convert_to_enum(arg_protocol: str) -> ProtocolType:
    if arg_protocol == 'tcp':
        return ProtocolType.TCP
    if arg_protocol == 'udp':
        return ProtocolType.UDP
    if arg_protocol == 'icmp':
        return ProtocolType.ICMP


def _check_hex(s: str):
    return bool(re.match(r'^[0-9a-fA-F]+', s))

def _check_ipv4(ip_address: str) -> bool:
    tokens = ip_address.split('.')
    if len(tokens) != 4:
        return False
    for token in tokens:
        if token == '0':
            continue
        if len(token) == 0:
            return False
        if not token.isdigit():
            return False
        if int(token) < 0 or int(token) > 255:
            return False
    return True

def _check_ipv6(ip_address: str) -> bool:
    if ':::' in ip_address: # ipv6 адрес не может иметь 3 двоеточия подряд
        return False
    tokens = ip_address.split(':')
    if len(tokens) > 8:
        return False
    for token in tokens:
        if len(token) > 4:
            return False
        if len(token) > 0 and not _check_hex(token):
            return False
    return True

def get_version(ip_address: str) -> IPVersion:
    if _check_ipv4(ip_address):
        return IPVersion.IPv4
    if _check_ipv6(ip_address):
        return IPVersion.IPv6