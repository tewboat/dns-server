from dns_server import ThreadingDnsServer

if __name__ == '__main__':
    with ThreadingDnsServer('localhost', 10) as server:
        server.serve_forever()
