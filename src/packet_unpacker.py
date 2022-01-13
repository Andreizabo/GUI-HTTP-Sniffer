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
        return eth, None, None, None
    if ip_header['protocol'] != 6:
        return eth, ip_header, None, None
    tcp_header = parser.parse_tcp_packet(packet[ip_header['ip_length']:])
    if tcp_header['source_port'] == 80 or tcp_header['destination_port'] == 80:
        parsed_http = parser.parse_http(packet[ip_header['ip_length'] + tcp_header['tcp_length']:])
        return eth, ip_header, tcp_header, parsed_http
    elif tcp_header['source_port'] == 443 or tcp_header['destination_port'] == 443:
        parsed_https = parser.parse_http(packet[ip_header['ip_length'] + tcp_header['tcp_length']:], https=True)
        return eth, ip_header, tcp_header, parsed_https
    else:
        return eth, ip_header, tcp_header, None
