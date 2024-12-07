from dataclasses import dataclass
from typing import Optional
from argparse import Namespace

from src.enums import Protocol
from src.utils import convert_to_enum


@dataclass
class Options:
    timeout: float = 2
    port: Optional[int] = None
    max_count_requests: Optional[int] = None
    verbose: bool = False


@dataclass
class TracerouteRequest:
    options: Options
    ip_address: str
    protocol: Protocol

    @classmethod
    def from_argument_parser(cls, args: Namespace):
        ip_address = args.ip_address
        protocol = convert_to_enum(args.protocol)
        options = Options(timeout=args.t, port=args.p,
                          max_count_requests=args.n, verbose=args.v)
        return cls(options=options, ip_address=ip_address, protocol=protocol)