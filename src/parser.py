import socket
import struct
import ipaddress

try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser


def parse_http(packet_data, https=False):
    if len(packet_data) < 1:
        return None
    if https:
        return {
            'https-encoded': str(packet_data),
            'observation': 'Protocol is HTTPS, cannot be decrypted'
        }
    http_parser = HttpParser()
    packet_data_len = len(packet_data)
    parsed_len = http_parser.execute(packet_data, packet_data_len)
    if parsed_len != packet_data_len:
        return {
            'data': str(packet_data),
            'observation': 'Could not decode HTTP'
        }
    else:
        http = {
            'verb': http_parser.get_method(),
            'headers': dict(http_parser.get_headers()),
        }
        body = http_parser.recv_body()
        try:
            http['body'] = body.decode('utf8')
            http['observation'] = 'Body decoded'
        except UnicodeDecodeError:
            http['body'] = str(body)
            http['observation'] = 'Body contains non-utf8 characters and can\'t be decoded'
        return http


def parse_tcp_packet(tcp_header):
    # https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    header = {}
    tcp_h = struct.unpack('! H H L L B B H H H', tcp_header[:20])
    header['source_port'] = tcp_h[0]
    header['destination_port'] = tcp_h[1]
    header['sequence_number'] = tcp_h[2]
    header['acknowledgement_number'] = tcp_h[3]
    header['data_offset'] = tcp_h[4] >> 4
    header['tcp_length'] = header['data_offset'] * 4
    header['flags'] = interpret_tcp_flags(tcp_h[4], tcp_h[5])
    header['window_size'] = tcp_h[6]
    header['checksum'] = tcp_h[7]
    header['urgent_pointer'] = tcp_h[8]
    return header


def interpret_tcp_flags(part1, part2):
    flags = []
    if part1 & 0b00000001:
        flags.append('NS (ECN-nonce - concealment protection)')
    if part2 >> 7:
        flags.append('CWR (Congestion window reduced)')
    if part2 >> 6:
        flags.append('ECE (ECN-Echo)')
    if part2 >> 5:
        flags.append('URG (Urgent)')
    if part2 >> 4:
        flags.append('ACK (Acknowledgement)')
    if part2 >> 3:
        flags.append('PSH (Push)')
    if part2 >> 2:
        flags.append('RST (Reset)')
    if part2 >> 1:
        flags.append('SYN (Synchronize sequence numbers)')
    if part2 & 0b00000001:
        flags.append('FIN (Last packet)')
    return flags


def parse_ipv4(ip_header):
    # https://en.wikipedia.org/wiki/IPv4#Packet_structure
    header = {}
    ip_h = struct.unpack('! B B H H H B B H 4s 4s', ip_header[:20])
    header['ip_version'] = 4
    header['ihl'] = ip_h[0] & 0b1111
    header['ip_length'] = header['ihl'] * 4
    header['traffic_class'] = {
        'ds': ip_h[1] >> 2,
        'ecn': ip_h[1] & 0b11
    }
    header['total_length'] = ip_h[2]
    header['identification'] = ip_h[3]
    header['flags'] = interpret_ipv4_flags(ip_h[4] >> 13)
    header['fragment_offset'] = ip_h[4] & 0b0001111111111111
    header['ttl'] = ip_h[5]
    header['protocol'] = ip_h[6]
    header['source_addr'] = str(ipaddress.IPv4Address(ip_h[8]))
    header['destination_addr'] = str(ipaddress.IPv4Address(ip_h[9]))
    return header


def interpret_ipv4_flags(flags):
    if flags == 1:
        return 'MF (More Fragments)'
    elif flags == 2:
        return 'DF (Don\'t fragment)'


def parse_ipv6(ip_header):
    # https://en.wikipedia.org/wiki/IPv6_packet
    header = {}
    data = struct.unpack('! L H B B 16s 16s', ip_header[:40])
    header['ip_version'] = 6
    header['traffic_class'] = {
        'ds': (data[0] << 6) >> 26,
        'ecn': (data[0] << 4) >> 28
    }
    header['ip_length'] = 40
    header['flow_label'] = data[0] & 0b11111111111111111111
    header['payload_length'] = data[1]
    header['protocol'] = data[2]
    header['hop_limit'] = data[3]
    header['source_addr'] = str(ipaddress.IPv6Address(data[4]))
    header['destination_addr'] = str(ipaddress.IPv6Address(data[5]))
    return header


def parse_ip_header(ip_header):
    version = ip_header[0] >> 4
    if version == 4:
        return parse_ipv4(ip_header)
    elif version == 6:
        return parse_ipv6(ip_header)


def parse_ethernet_frame(frame):
    eth = {}
    destination_mac, source_mac, ether_type = struct.unpack('! 6s 6s H', frame[:14])
    eth['destination_mac_address'] = destination_mac.hex(':')
    eth['source_mac_address'] = source_mac.hex(':')
    eth['ip_version'] = get_ipv(ether_type)
    return eth


def get_ipv(ether_type):
    if ether_type == 0x0800:
        return 4
    elif ether_type == 0x86DD:
        return 6
