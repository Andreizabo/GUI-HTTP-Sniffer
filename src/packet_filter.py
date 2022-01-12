
class PacketFilter:
    """
    A class for filtering packets.

    Attributes:
        allowed_ports   -- if not empty, only packets coming from/to ports in this array will be allowed
        blocked_ports   -- if not empty, all packets coming from/to ports in this array will be blocked
        allowed_ips     -- if not empty, only packets coming from/to IPs in this array will be allowed
        blocked_ips     -- if not empty, all packets coming from/to IPs in this array will be blocked
        ipv4_only       -- if set, only IPV4 packets will be allowed
        ipv6_only       -- if set, only IPV6 packets will be allowed

    Methods:
        modify()    -- Modifies the settings of the filter
        verify()    -- Verifies if sent headers follow the rules set up in the filter
    """
    def __init__(self, allowed_ports=None, blocked_ports=None, allowed_ips=None, blocked_ips=None, ipv4_only=False, ipv6_only=False):
        """
        Initializes the filter with default values.

        Keyword arguments:
            allowed_ports   -- if not empty, only packets coming from/to ports in this array will be allowed (default - None)
            blocked_ports   -- if not empty, all packets coming from/to ports in this array will be blocked (default - None)
            allowed_ips     -- if not empty, only packets coming from/to IPs in this array will be allowed (default - None)
            blocked_ips     -- if not empty, all packets coming from/to IPs in this array will be blocked (default - None)
            ipv4_only       -- if set, only IPV4 packets will be allowed (default - None)
            ipv6_only       -- if set, only IPV6 packets will be allowed (default - None)
        """
        self.allowed_ports = allowed_ports
        self.blocked_ports = blocked_ports
        self.allowed_ips = allowed_ips
        self.blocked_ips = blocked_ips
        self.ipv4_only = ipv4_only
        self.ipv6_only = ipv6_only

    def modify(self, allowed_ports=None, blocked_ports=None, allowed_ips=None, blocked_ips=None, ipv4_only=False, ipv6_only=False):
        """
        Modifies the settings of the filter.

        Keyword arguments:
            allowed_ports   -- if not empty, only packets coming from/to ports in this array will be allowed (default - None)
            blocked_ports   -- if not empty, all packets coming from/to ports in this array will be blocked (default - None)
            allowed_ips     -- if not empty, only packets coming from/to IPs in this array will be allowed (default - None)
            blocked_ips     -- if not empty, all packets coming from/to IPs in this array will be blocked (default - None)
            ipv4_only       -- if set, only IPV4 packets will be allowed (default - None)
            ipv6_only       -- if set, only IPV6 packets will be allowed (default - None)
        """
        self.allowed_ports = allowed_ports
        self.blocked_ports = blocked_ports
        self.allowed_ips = allowed_ips
        self.blocked_ips = blocked_ips
        self.ipv4_only = ipv4_only
        self.ipv6_only = ipv6_only

    def verify(self, iph, tcp):
        """
        Verifies if sent headers follow the rules set up in the filter.

        Keyword arguments:
            iph -- the IP_header
            tcp -- the TCP_header

        Returns:
            True    -- if all the rules are satisfied
            False   -- if any of the rules is not satisfied
        """
        if self.ipv4_only and iph['ip_version'] != 4:
            return False
        if self.ipv6_only and iph['ip_version'] != 6:
            return False
        if self.allowed_ips is not None and len(self.allowed_ips) > 0:
            if iph['source_addr'] not in self.allowed_ips and iph['destination_addr'] not in self.allowed_ips:
                return False
        if self.blocked_ips is not None and len(self.blocked_ips) > 0:
            if iph['source_addr'] in self.blocked_ips or iph['destination_addr'] in self.blocked_ips:
                return False
        if self.allowed_ports is not None and len(self.allowed_ports) > 0:
            if str(tcp['source_port']) not in self.allowed_ports and str(tcp['destination_port']) not in self.allowed_ports:
                return False
        if self.blocked_ports is not None and len(self.blocked_ports) > 0:
            if str(tcp['source_port']) not in self.blocked_ports or str(tcp['destination_port']) not in self.blocked_ports:
                return False
        return True
