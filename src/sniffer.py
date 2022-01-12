import os
import socket
import utils


class Sniffer:
    """
    A class for sniffing packets.

    Attributes:
        ip      -- the IP address the socket will be bound to
        port    -- the port the socket will be bound to
        socket  -- the socket which will capture the packets

    Methods:
        open_listener()     -- Creates and binds the socket, with options specific to the OS
        receive_all_pkg()   -- Updates the SIO_RCVALL option for the socket
        sniff()             -- Uses the socket to capture a packet
        close()             -- Closes the socket
    """
    def __init__(self, ip=socket.gethostbyname(socket.gethostname()), port=0):
        """
        Initializes the ip and the port for the socket.

        Keyword arguments:
            ip   -- the IP address the socket will be bound to (default - the hostname)
            port -- the port the socket will be bound to (default - 0, listen on all ports)
        """
        self.ip = ip
        self.port = port
        self.socket = None

    def open_listener(self):
        """
        Creates and binds the socket to the IP and port set in the constructor, with options specific to the OS.
        For Windows, the socket is created with IPPROTO_IP and other options which allow receiving all outbound packets.
        For Linux, the socket is created with ntohs(0x0003), meaning it will catch everything, including Ethernet frames.
        """
        if os.name == 'nt':
            # Create the socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            # Allow the address to be reused
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind the socket to the given IP on the given port
            self.socket.bind((self.ip, self.port))
            # Modify the IPPROTO_IP option to include the IP headers
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Receive all packages
            self.receive_all_pkg(True)
        elif os.name == 'posix':
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    def receive_all_pkg(self, option):
        """
        Updates the SIO_RCVALL option for the socket according to `option`.

        Keyword arguments:
            option  -- if True, SIO_RCVALL will be enabled, otherwise it will be disabled
        """
        try:
            # If SIO_RCVALL is set to True all packages will be received
            self.socket.ioctl(socket.SIO_RCVALL, int(option))
        except AttributeError as err:
            utils.print_err(f'{err}\nSocket was not initialized')
            exit()

    def sniff(self, buffer_size=65565):
        """
        Uses the socket to receive up to `buffer_size` bytes.

        Keyword arguments:
            buffer_size -- the maximum amount of bytes that can be received at once (default - 65565)

        Returns:
            data        -- the data received by the socket
        """
        try:
            data = self.socket.recvfrom(buffer_size)
            return data
        except AttributeError as err:
            utils.print_err(f'{err}\nSocket was not initialized')
            exit()

    def close(self):
        """Closes the socket."""
        try:
            self.socket.close()
        except AttributeError as err:
            utils.print_err(f'{err}\nSocket was not initialized')
            exit()
