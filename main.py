from dns_server import DnsServer
import threading

if __name__ == '__main__':
    server = DnsServer("192.168.0.152", 53)
    threading.Thread(target=server.run).run()
