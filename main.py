from dns_server import DnsServer


if __name__ == '__main__':
    server = DnsServer("localhost", 5001)
    server.run()
