import sniffer

if __name__ == "__main__":
    sniffer = sniffer.Sniffer()
    sniffer.open_listener()
    for i in range(10):
        print(sniffer.sniff())
