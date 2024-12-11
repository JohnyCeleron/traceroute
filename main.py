from src.request_builder import TracerouteRequest
from src.response_builder import Traceroute
from console_parser import get_arguments
from scapy.all import IP, ICMP, sr1, UDP, TCP, IPv6


def main():
    arguments = get_arguments()
    request = TracerouteRequest.from_argument_parser(arguments)
    traceroute = Traceroute(request)
    for response in traceroute.get_responses():
        print(response)

def test():
    destination_ip = '2606:4700:4700::1111'
    for ttl in range(1, 256):
        packet = IPv6(dst=destination_ip, hlim=ttl) / UDP(dport=33434)
        reply = sr1(packet, timeout=5, verbose=0)
        if reply is None:
            print(f"TTL={ttl}: Нет ответа")
        elif reply.type == 3:  # Целевой узел достигнут
            print(f"TTL={ttl}: Достиг {reply.src} {reply.time - packet.sent_time}")
            break
        else:
            print(f"TTL={ttl}: {reply.src} {reply.time - packet.sent_time}")

if __name__ == '__main__':
    main()
    #test()