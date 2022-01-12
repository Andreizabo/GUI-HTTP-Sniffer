import sniffer
import packet_unpacker
import json
import packet_filter


if __name__ == "__main__":
    the_sniffer = sniffer.Sniffer()
    the_sniffer.open_listener()
    try:
        while not False:
            packet, (address, port) = the_sniffer.sniff()
            eth, iph, tcp, http = packet_unpacker.unpack(packet)
            if tcp is not None:
                p_filter = packet_filter.PacketFilter(allowed_ports=[80, 443])
                if p_filter.verify(iph, tcp):
                    with open('log.json', 'a') as w:
                        printable = {
                            'Ethernet_frame': eth,
                            'Ip_header': iph,
                            'Tcp_header': tcp,
                            'Http_header': http
                        }
                        w.write(json.dumps(printable, indent=4))
                        w.write(',\n')
    except KeyboardInterrupt:
        the_sniffer.close()
