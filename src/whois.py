import socket


def get_asn(ip_address):
    rir_server = _get_rir_whois_server(ip_address)
    if rir_server:
        whois_result = _query_whois(ip_address, rir_server)
        if whois_result:
            return _extract_asn(whois_result)
    return 'NA'

def _query_whois(ip_address: str, rir_server: str): #TODO IPv6
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((rir_server, 43))
            s.send(f'{ip_address} \r\n'.encode())
            res = b''
            while True:
                try:
                    buf = s.recv(4096)
                except socket.error:
                    break

                if buf:
                    res += buf
                else:
                    break

            return res.decode()
    except:
        return None


def _get_rir_whois_server(ip_address):
    iana_response = _query_whois(ip_address, "whois.iana.org")
    if iana_response is not None:
        for line in iana_response.splitlines():
            if line.lower().startswith("refer:") or line.lower().startswith("whois:"): #TODO: прочитать про эту метку
                return line.split(":")[1].strip()
    return None


def _extract_asn(whois_result):
    for line in whois_result.splitlines():
        lower_line = line.lower()
        if lower_line.startswith("origin:") or lower_line.startswith("originas:"):
            data = line.strip().split(" ")
            if len(data) == 1:
                return 'NA'
            return data[-1]
    return 'NA'


if __name__ == '__main__':
    print(get_asn('85.235.63.182'))