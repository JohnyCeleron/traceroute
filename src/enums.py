from enum import StrEnum


class Protocol(StrEnum):
    TCP = 'TCP',
    UDP = 'UDP'
    ICMP = 'ICMP'


class IPVersion(StrEnum):
    IPv4 = 'IPv4',
    IPv6 = 'IPv6'