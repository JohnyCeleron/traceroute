from dataclasses import dataclass
from typing import Optional
from argparse import Namespace, ArgumentError

from src.enums import ProtocolType
from src.utils import convert_to_enum, get_version

@dataclass
class Options:
    timeout: float = 2
    port: Optional[int] = None
    max_count_requests: Optional[int] = None
    verbose: bool = False

DEFAULT_PORTS = {
    ProtocolType.UDP: 33434,
    ProtocolType.TCP: 80
}

@dataclass
class TracerouteRequest:
    options: Options
    ip_address: str
    protocol: ProtocolType

    @classmethod
    def from_argument_parser(cls, args: Namespace):
        cls._validate(args)
        ip_address = args.ip_address
        protocol = convert_to_enum(args.protocol)
        port = args.p
        if port is None and protocol != ProtocolType.ICMP:
            port = DEFAULT_PORTS[protocol]
        options = Options(timeout=args.t, port=port,
                          max_count_requests=args.n, verbose=args.v)
        return cls(options=options, ip_address=ip_address, protocol=protocol)

    @staticmethod
    def _validate(args: Namespace):
        if get_version(args.ip_address) is None:
            raise AssertionError('IP Address is not valid')
        if args.t <= 0:
            raise AssertionError('Timeout must be positive')
        if args.p is not None and (0 > args.p or args.p > 65535):
            raise AssertionError('Port must be between 0 and 65535')
        if args.n is not None and args.n <= 0:
            raise AssertionError('Max count requests must be positive')