from argparse import ArgumentError

from src.request_builder import TracerouteRequest
from src.response_builder import TracerouteResponse
from console_parser import get_arguments
from scapy.all import *

def main():
    arguments = get_arguments()
    try:
        request = TracerouteRequest.from_argument_parser(arguments)
        response = TracerouteResponse.from_request(request)
        print(response)
    except ArgumentError as e:
        print(e)
    finally:
        exit()


# TODO: надо научиться обрабатывать случай, когда ttl > 255
# TODO: whois
def test():
    host = '2001:0db8:abf2:29ea:5298:ad71:2ca0:4ff1'
    port = 20
    flag = True
    ttl = 1
    hops = []
    while flag:
        ans = sr1(IPv6(dst=host, ttl=ttl) / ICMP(), verbose=0, timeout=5)
        print(ans)
        if ans is None:
            hops.append('*')
            ttl += 1
            continue
        icmp_answer = ans.getlayer(ICMP)
        print(repr(icmp_answer))
        if icmp_answer.type == 0:
            hops.append(host)# checking for  ICMP echo-reply
            flag = False
        else:
            hops.append(icmp_answer.dst)  # storing the src ip from ICMP error message
            ttl += 1
    i = 1
    for hop in hops:
        print(f'{i} {hop}')
        i += 1

if __name__ == '__main__':
    test()
    #main()