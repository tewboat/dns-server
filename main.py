from dns_server import ThreadingDnsServer
import threading

if __name__ == '__main__':
    with ThreadingDnsServer('localhost', 10) as server:
        server.serve_forever()
