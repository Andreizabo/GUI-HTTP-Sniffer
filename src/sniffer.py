import os
import socket
import utils


class Sniffer:
    def __init__(self, ip=socket.gethostbyname(socket.gethostname()), port=0):
        self.ip = ip
        self.port = port
        self.socket = None

    def open_listener(self):
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
        try:
            # If SIO_RCVALL is set to True all packages will be received
            self.socket.ioctl(socket.SIO_RCVALL, int(option))
        except AttributeError as err:
            utils.print_err(f'{err}\nSocket was not initialized')
            exit()

    def sniff(self, buffer_size=65565):
        try:
            data = self.socket.recvfrom(buffer_size)
            if os.name == 'nt':
                return data
            elif os.name == 'posix':
                return data[0], (data[1], None)
            else:
                return None
        except AttributeError as err:
            utils.print_err(f'{err}\nSocket was not initialized')
            exit()

    def close(self):
        self.socket.close()
