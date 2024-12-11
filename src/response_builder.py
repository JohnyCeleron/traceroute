from typing import Generator

from scapy.all import *

from src.sender_packet import sender_by_ip_version
from src.request_builder import TracerouteRequest
from src.utils import get_version


class Traceroute:
    def __init__(self, request: TracerouteRequest) -> None:
        self.request = request
        self.ip_version = get_version(self.request.ip_address)

    def get_responses(self) -> Generator[str]:
        max_count_request = self.request.options.max_count_requests if self.request.options.max_count_requests else 256
        sender = sender_by_ip_version[self.ip_version](self.request)
        for ttl in range(1, min(max_count_request + 1, 256)):
            response = sender.get_simple_response(ttl)
            yield str(response)
            if response.is_finished:
                break
        else:
            yield "Traceroute has reached the ttl limit of 255"