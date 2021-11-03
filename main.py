from dns_server import DnsServer

if __name__ == '__main__':
    server = DnsServer("192.168.0.148", 53)
    server.run()
