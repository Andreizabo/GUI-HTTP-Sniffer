import os
import parser


def unpack(packet):
    """
    Unpacks a packet.
    For Linux distributions, it will first try to unpack the Ethernet frame,
    the same steps are followed regardless of OS.
    The IP header will be unpacked, both IPV4 and IPV6 are supported.
    If the protocol obtained is 6 (TCP), the TCP header will be unpacked.
    If either the source port or the destination port is 80, the HTTP header will be unpacked.
    If the port is 443, the HTTPS header will not be decoded, but will be returned.

    Keyword arguments:
        packet  -- the packet to be unpacked

    Returns:
        headers -- a tuple of the 4 parsed headers (ethernet frame, ip, tcp, http);
                   any of them can be None, if the parsing failed at their step.
    """
    if os.name == 'posix':
        eth = parser.parse_ethernet_frame(packet)
        packet = packet[14:]
    else:
        eth = None
    ip_header = parser.parse_ip_header(packet)
    if ip_header is None:
        return eth, None, None, None, None
    if ip_header['protocol'] != 6:
        return eth, ip_header, None, None, None
    tcp_header = parser.parse_tcp_packet(packet[ip_header['ip_length']:])
    guess = guess_protocol(ip_header, tcp_header, packet[ip_header['ip_length'] + tcp_header['tcp_length']:])
    if tcp_header['source_port'] == 80 or tcp_header['destination_port'] == 80:
        parsed_http = parser.parse_http(packet[ip_header['ip_length'] + tcp_header['tcp_length']:])
        return eth, ip_header, tcp_header, parsed_http, guess
    elif tcp_header['source_port'] == 443 or tcp_header['destination_port'] == 443:
        parsed_https = parser.parse_http(packet[ip_header['ip_length'] + tcp_header['tcp_length']:], https=True)
        return eth, ip_header, tcp_header, parsed_https, guess
    else:
        return eth, ip_header, tcp_header, None, guess


def guess_protocol(iph, tcp, packet):
    """
    Tries to guess the protocol of the packet.
    If it is tcp and is sent on port 80, the contents of the packet will be checked.
    If it starts with `HTTP/`, then it is certainly HTTP.
    If it starts with a verb and then has `HTTP/` in it, then it is certainly HTTP. If it doesn't have `HTTP/` after,
    we can say with a certainty of 90% that it is HTTP.
    If it is only sent on port 80 and no other conditions are met, it is HTTP with a certainty of 50%
    If it is tcp and is sent on port 443, it is HTTPS with a certainty of 50%. We can't verify its contents
    If it is tcp and is sent on port 21, it is FTP with a certainty of 50%.

    Keyword arguments:
        iph     -- the unpacked and parsed IP header
        tcp     -- the unpacked and parsed TCP header
        packet  -- the packet to be verified

    Returns:
        guess   -- a tuple containing the guessed protocol and its certainty
    """
    http_verbs = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']
    if iph['protocol'] == 6:
        if 80 in (tcp['source_port'], tcp['destination_port']):
            check_beg = packet[:10].decode('utf8')
            if check_beg.startswith('HTTP/'):
                return 'HTTP', '100%'
            for verb in http_verbs:
                if check_beg.startswith(verb):
                    further_http = packet[len(verb):len(verb)+12].decode('utf8')
                    if 'HTTP/' in further_http:
                        return 'HTTP', '100%'
                    return 'HTTP', '90%'
            return 'HTTP', '50%'
        elif 443 in (tcp['source_port'], tcp['destination_port']):
            return 'HTTPS', '50%'
        elif 21 in (tcp['source_port'], tcp['destination_port']):
            return 'FTP', '50%'

