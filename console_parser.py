import argparse


def get_arguments():
    parser = argparse.ArgumentParser(
        description="Traceroute utility",
    )
    _add_optional_arguments(parser)
    _add_positional_arguments(parser)
    return parser.parse_args()


def _add_positional_arguments(parser):
    parser.add_argument("ip_address", type=str,
                        help="IP address to scan"
                        )
    parser.add_argument("protocol", choices=["tcp", "udp", "icmp"],
                        help="Protocol")


def _add_optional_arguments(parser):
    parser.add_argument("-t", type=float, default=2.0,
                        help="Timeout for waiting response in seconds (default: 2s)"
                        )
    parser.add_argument("-p", type=int, default=None,
                        help="Port (for tcp or udp)")
    parser.add_argument("-v", action="store_true",
                        help="output of the autonomous system number for each ip address")
    parser.add_argument("-n", type=int, default=None,
                        help="max count requests"
                        )