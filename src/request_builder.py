from dataclasses import dataclass
from typing import Optional
from argparse import Namespace, ArgumentError

from src.enums import Protocol
from src.utils import convert_to_enum, get_version

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
        cls._validate(args)
        ip_address = args.ip_address
        protocol = convert_to_enum(args.protocol)
        options = Options(timeout=args.t, port=args.p,
                          max_count_requests=args.n, verbose=args.v)
        return cls(options=options, ip_address=ip_address, protocol=protocol)

    @staticmethod
    def _validate(args: Namespace):
        if get_version(args.ip_address) is None:
            raise ArgumentError('IP Address is not valid')
        if args.t <= 0:
            raise ArgumentError('Timeout must be positive')
        if args.p < 0 and args.p > 65535:
            raise ArgumentError('Port must be between 0 and 65535')
        if args.max_count_requests <= 0:
            raise ArgumentError('Max count requests must be positive')