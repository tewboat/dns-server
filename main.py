from dns_server import DnsServer


def main():
    server = DnsServer("192.168.0.148", 53)
    server.run()


if __name__ == '__main__':
    main()
