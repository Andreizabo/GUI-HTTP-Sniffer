import os
import parser


def unpack(packet):
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
