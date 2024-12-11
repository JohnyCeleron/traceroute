from src.enums import IPVersion, ProtocolType
from src.request_builder import TracerouteRequest
from src.simple_response import SimpleResponse
from src.whois import get_asn
from abc import ABC, abstractmethod
from scapy.all import *


class SenderPacketFactory(ABC):
    def __init__(self, request: TracerouteRequest):
        self.destination_ip = request.ip_address
        self.protocol = request.protocol
        self.verbose = request.options.verbose
        self.timeout = request.options.timeout
        self.port = request.options.port

    def get_simple_response(self, ttl):
        if self.protocol == ProtocolType.ICMP:
            return self.send_icmp(ttl)
        if self.protocol == ProtocolType.TCP:
            return self.send_tcp(ttl)
        if self.protocol == ProtocolType.UDP:
            return self.send_udp(ttl)

    @abstractmethod
    def send_tcp(self, ttl: int) -> SimpleResponse:
        pass

    @abstractmethod
    def send_udp(self, ttl: int) -> SimpleResponse:
        pass

    @abstractmethod
    def send_icmp(self, ttl: int) -> SimpleResponse:
        pass


class IPv4SenderPacket(SenderPacketFactory):
    def send_icmp(self, ttl: int) -> SimpleResponse:
        packet = IP(dst=self.destination_ip, ttl=ttl) / ICMP()
        reply = sr1(packet, timeout=self.timeout, verbose=0)
        if reply is None:
            return SimpleResponse(number=ttl, not_answer=True)
        asn = get_asn(reply.src)
        if reply.haslayer(ICMP) and reply[ICMP].type == 0:
            return SimpleResponse(number=ttl, ip=reply.src, time_in_ms=(reply.time - packet.sent_time) * 1000,
                                  number_autonomous_system=asn, verbose=self.verbose, is_finished=True)
        if reply.haslayer(ICMP) and reply[ICMP].type == 11:
            return SimpleResponse(number=ttl, ip=reply.src, time_in_ms=(reply.time - packet.sent_time) * 1000,
                                  number_autonomous_system=asn, verbose=self.verbose, is_finished=False)

    def send_udp(self, ttl: int) -> SimpleResponse:
        packet = IP(dst=self.destination_ip, ttl=ttl) / UDP(dport=self.port)
        reply = sr1(packet, timeout=self.timeout, verbose=0)
        if reply is None:
            return SimpleResponse(number=ttl, not_answer=True)
        asn = get_asn(reply.src)
        is_finished = reply.type == 3
        return SimpleResponse(number=ttl, ip=reply.src, time_in_ms=(reply.time - packet.sent_time) * 1000,
                              number_autonomous_system=asn, verbose=self.verbose, is_finished=is_finished)

    def send_tcp(self, ttl: int) -> SimpleResponse:
        packet = IP(dst=self.destination_ip, ttl=ttl) / TCP(dport=self.port, flags='S')
        reply = sr1(packet, timeout=self.timeout, verbose=0)
        if reply is None:
            return SimpleResponse(number=ttl, not_answer=True)
        asn = get_asn(reply.src)
        is_finished = reply.haslayer(TCP) and reply[TCP].flags == 'SA'
        return SimpleResponse(number=ttl, ip=reply.src, time_in_ms=(reply.time - packet.sent_time) * 1000,
                              number_autonomous_system=asn, verbose=self.verbose, is_finished=is_finished)

class IPv6SenderPacket(SenderPacketFactory):
    def send_icmp(self, ttl: int) -> SimpleResponse:
        pass

    def send_udp(self, ttl: int) -> SimpleResponse:
        packet = IPv6(dst=self.destination_ip, hlim=ttl) / UDP(dport=self.port)
        reply = sr1(packet, timeout=self.timeout, verbose=0)
        if reply is None:
            return SimpleResponse(number=ttl, not_answer=True)
        asn = get_asn(reply[IPv6].src)
        if reply.haslayer(ICMPv6TimeExceeded):
            return SimpleResponse(number=ttl, ip=reply[IPv6].src, time_in_ms=(reply.time - packet.sent_time) * 1000,
                                  number_autonomous_system=asn, verbose=self.verbose)
        if reply.haslayer(UDP):
            return SimpleResponse(number=ttl, ip=reply[IPv6].src, time_in_ms=(reply.time - packet.sent_time) * 1000,
                                  number_autonomous_system=asn, verbose=self.verbose)

    def send_tcp(self, ttl: int) -> SimpleResponse:
        pass


sender_by_ip_version = {
    IPVersion.IPv4: IPv4SenderPacket,
    IPVersion.IPv6: IPv6SenderPacket
}