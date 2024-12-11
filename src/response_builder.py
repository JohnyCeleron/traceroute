from dataclasses import dataclass
from typing import Generator
from src.enums import IPVersion, ProtocolType
from src.request_builder import TracerouteRequest
from scapy.all import *
from src.whois import get_asn
from src.utils import get_version


@dataclass
class SimpleResponse:
    number: int
    ip: str = ''
    time_in_ms: float = 0.0
    number_autonomous_system: int = 0
    verbose: bool = False
    not_answer: bool = False
    is_finished: bool = False

    def __str__(self) -> str:
        if self.not_answer:
            return f'{self.number} *'
        return f'{self.number} {self.ip} {self.time_in_ms} {self.number_autonomous_system if self.verbose else ""}'


class Traceroute:
    def __init__(self, request: TracerouteRequest) -> None:
        self.request = request
        self.ip_version = get_version(self.request.ip_address)

    def get_responses(self) -> Generator[str]:
        max_count_request = self.request.options.max_count_requests if self.request.options.max_count_requests else 256
        for ttl in range(1, min(max_count_request + 1, 256)):
            response = self._create_simple_response(ttl)
            yield str(response)
            if response.is_finished:
                break
        else:
            yield "Traceroute has reached the ttl limit of 255"


    def _create_simple_response(self, ttl: int) -> SimpleResponse:
        destination_ip = self.request.ip_address
        protocol = self.request.protocol
        verbose = self.request.options.verbose
        timeout = self.request.options.timeout
        number = ttl

        # TODO: отрефакторить
        if self.ip_version == IPVersion.IPv4:
            if protocol == ProtocolType.UDP:
                packet = IP(dst=destination_ip, ttl=ttl) / UDP(dport=self.request.options.port)
                reply = sr1(packet, timeout=timeout, verbose=0)
                if reply is None:
                    return SimpleResponse(number=number, not_answer=True)
                asn = get_asn(reply.src)
                is_finished = reply.type == 3
                return SimpleResponse(number=number, ip=reply.src, time_in_ms=(reply.time - packet.sent_time) * 1000,
                                      number_autonomous_system=asn, verbose=verbose, is_finished=is_finished)
            if protocol == ProtocolType.TCP:
                packet = IP(dst=destination_ip, ttl=ttl) / TCP(dport=self.request.options.port, flags='S')
                reply = sr1(packet, timeout=timeout, verbose=0)
                if reply is None:
                    return SimpleResponse(number=number, not_answer=True)
                asn = get_asn(reply.src)
                is_finished = reply.haslayer(TCP) and reply[TCP].flags == 'SA'
                return SimpleResponse(number=number, ip=reply.src, time_in_ms=(reply.time - packet.sent_time) * 1000,
                                      number_autonomous_system=asn, verbose=verbose, is_finished=is_finished)
            if protocol == ProtocolType.ICMP:
                packet = IP(dst=destination_ip, ttl=ttl) / ICMP()
                reply = sr1(packet, timeout=timeout, verbose=0)
                if reply is None:
                    return SimpleResponse(number=number, not_answer=True)
                asn = get_asn(reply.src)
                if reply.haslayer(ICMP) and reply[ICMP].type == 0:
                    return SimpleResponse(number=number, ip=reply.src, time_in_ms=(reply.time - packet.sent_time) * 1000,
                                          number_autonomous_system=asn, verbose=verbose, is_finished=True)
                if reply.haslayer(ICMP) and reply[ICMP].type == 11:
                    return SimpleResponse(number=number, ip=reply.src, time_in_ms=(reply.time - packet.sent_time) * 1000,
                                          number_autonomous_system=asn, verbose=verbose, is_finished=False)

        else: #TODO протестить IPv6(ПОКА на эту версию протокола забить)
            if protocol == ProtocolType.UDP:
                packet = IPv6(dst=destination_ip, hlim=ttl) / UDP(dport=self.request.options.port)
                reply = sr1(packet, timeout=timeout, verbose=0)
                if reply is None:
                    return SimpleResponse(number=number, not_answer=True)
                asn = get_asn(reply[IPv6].src)
                if reply.haslayer(ICMPv6TimeExceeded):
                    return SimpleResponse(number=number, ip=reply[IPv6].src, time_in_ms=(reply.time - packet.sent_time) * 1000,
                                          number_autonomous_system=asn, verbose=verbose)
                if reply.haslayer(UDP):
                    return SimpleResponse(number=number, ip=reply[IPv6].src, time_in_ms=(reply.time - packet.sent_time) * 1000,
                                          number_autonomous_system=asn, verbose=verbose)