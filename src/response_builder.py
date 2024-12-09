from dataclasses import dataclass
from ipaddress import ip_address

from src.request_builder import TracerouteRequest

@dataclass
class SimpleResponse:
    number: int
    ip: str
    time_in_ms: float
    number_autonomous_system: int
    verbose: bool

    def __str__(self) -> str:
        return f'{self.number} {self.ip} {self.time_in_ms} {self.number_autonomous_system if self.verbose else ""}'


@dataclass
class TracerouteResponse:
    simple_responses: list[SimpleResponse]

    @classmethod
    def from_request(cls, request: TracerouteRequest):
        ip_address = request.ip_address

        pass # TODO: вот тут уже начинается логика

    def __str__(self) -> str:
        return '\n'.join(str(simple_response) for simple_response in self.simple_responses)