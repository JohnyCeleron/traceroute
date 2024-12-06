from src.protocol import Protocol


def convert_to_enum(arg_protocol: str) -> Protocol:
    if arg_protocol == 'tcp':
        return Protocol.TCP
    if arg_protocol == 'udp':
        return Protocol.UDP
    if arg_protocol == 'icmp':
        return Protocol.ICMP
