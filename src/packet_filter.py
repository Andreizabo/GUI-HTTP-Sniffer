
class PacketFilter:
    def __init__(self, allowed_ports=None, blocked_ports=None, allowed_ips=None, blocked_ips=None, ipv4_only=False, ipv6_only=False):
        self.allowed_ports = allowed_ports
        self.blocked_ports = blocked_ports
        self.allowed_ips = allowed_ips
        self.blocked_ips = blocked_ips
        self.ipv4_only = ipv4_only
        self.ipv6_only = ipv6_only

    def verify(self, iph, tcp):
        if self.ipv4_only and iph['version'] != 4:
            return False
        if self.ipv6_only and iph['version'] != 6:
            return False
        if self.allowed_ips is not None:
            if iph['source_addr'] not in self.allowed_ips and iph['destination_addr'] not in self.allowed_ips:
                return False
        if self.blocked_ips is not None:
            if iph['source_addr'] in self.blocked_ips or iph['destination_addr'] in self.blocked_ips:
                return False
        if self.allowed_ports is not None:
            if tcp['source_port'] not in self.allowed_ports and tcp['destination_port'] not in self.allowed_ports:
                return False
        if self.blocked_ports is not None:
            if tcp['source_port'] not in self.blocked_ports or tcp['destination_port'] not in self.blocked_ports:
                return False
        return True
