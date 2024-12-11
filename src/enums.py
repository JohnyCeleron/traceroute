from enum import StrEnum


class ProtocolType(StrEnum):
    TCP = 'TCP',
    UDP = 'UDP',
    ICMP = 'ICMP'


class IPVersion(StrEnum):
    IPv4 = 'IPv4',
    IPv6 = 'IPv6'