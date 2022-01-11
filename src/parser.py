import socket
import struct


def parse_tcp_packet(tcp_header):
    # https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    header = {}
    tcp_h = struct.unpack('!HHLLBBHHH', tcp_header)
    header['source_port'] = tcp_h[0]
    header['destination_port'] = tcp_h[1]
    header['sequence_number'] = tcp_h[2]
    header['acknowledgement_number'] = tcp_h[3]
    header['data_offset'] = tcp_h[4] >> 4
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
    ip_h = struct.unpack('!BBHHHBBH4s4s', ip_header[:20])
    header['version'] = 4
    header['ihl'] = ip_h[0] & 0b1111
    header['ipv4_length'] = header['ihl'] * 4
    header['dscp'] = ip_h[1] >> 2
    header['ecn'] = ip_h[1] & 0b11
    header['total_length'] = ip_h[2]
    header['identification'] = ip_h[3]
    header['flags'] = interpret_ipv4_flags(ip_h[4] >> 13)
    header['fragment_offset'] = ip_h[4] & 0b0001111111111111
    header['ttl'] = ip_h[5]
    header['protocol'] = ip_h[6]
    header['source_addr'] = socket.inet_ntoa(ip_h[8])
    header['destination_addr'] = socket.inet_ntoa(ip_h[9])
    return header


def interpret_ipv4_flags(flags):
    if flags == 1:
        return 'MF (More Fragments)'
    elif flags == 2:
        return 'DF (Don\'t fragment)'


def parse_ipv6(ip_header):
    pass


def parse_ip_header(ip_header):
    version = ip_header[0] >> 4
    if version == 4:
        return parse_ipv4(ip_header)
    elif version == 6:
        return parse_ipv6(ip_header)
