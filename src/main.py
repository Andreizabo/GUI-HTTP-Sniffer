import sniffer
import parser


if __name__ == "__main__":
    the_sniffer = sniffer.Sniffer(port=80)
    the_sniffer.open_listener()
    try:
        while not False:
            packet, (address, port) = the_sniffer.sniff()
            ip_header = parser.parse_ip_header(packet)
            tcp_header = parser.parse_tcp_packet(packet[ip_header['ipv4_length']:ip_header['ipv4_length']+20])
            print("Start packet")
            print(ip_header)
            print(tcp_header)
            print("Fin packet")
    except KeyboardInterrupt:
        the_sniffer.close()
