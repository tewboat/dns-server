from dns_server import DnsServer

if __name__ == '__main__':
    server = DnsServer("192.168.1.101", 53)
    server.run()
