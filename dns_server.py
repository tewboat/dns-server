import json
import random
import socket
import struct
import ipaddress



class DnsServer:
    root_server_address = ('198.41.0.4', 53)

    def __init__(self, host, port):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((host, port))
        self.request_generator = DnsRequestGenerator()
        self.response_parser = DnsResponseParser()

    def run(self):
        while True:
            data, ipaddress = self.server_socket.recvfrom(256)
            self.__handle_client__(data, ipaddress)

    def __handle_client__(self, data, client):
        parts = data.split()
        try:
            request = self.request_generator.generate_request(parts[0], parts[1])
            if len(parts) == 2:
                self.server_socket.sendto(request, self.root_server_address)
            elif len(parts) == 3:
                self.server_socket.sendto(request, (parts[2], 53))
            response, server = self.server_socket.recvfrom(1024)
            parsed_response = self.response_parser.parse_response(response)
            json_string = json.dumps(parsed_response)
            self.server_socket.sendto(json_string.encode(), client)
        except ValueError or TypeError:
            self.server_socket.sendto('Refused: check the correctness of the request.'.encode(), client)
        except IndexError:
            self.server_socket.sendto('Refused: fewer arguments passed than necessary.'.encode(), client)


class DnsRequestGenerator:
    qtypes = {
        b'A': 1,
        b'AAAA': 28,
        b'MX': 15,
        b'NS': 2
    }

    def generate_request(self, url, r_type):
        header = self.__generate_header__(0, 0)
        body = self.__generate_body__(url, r_type)
        return b''.join([header, body])

    def __generate_header__(self, opcode, rd):
        id = struct.pack('>H', random.randint(0, 65535))
        flags = struct.pack('>H', (((opcode << 3) + rd) << 8))
        qdcount = struct.pack('>H', 1)
        ancount = struct.pack('>H', 0)
        nscount = struct.pack('>H', 0)
        arcount = struct.pack('>H', 0)
        return b''.join([id, flags, qdcount, ancount, nscount, arcount])

    def __generate_body__(self, url, r_type):
        if r_type not in self.qtypes:
            raise ValueError(f'Incorrect request type: {r_type}')
        body = []
        labels = url.split(b'.')
        for label in labels:
            body.append(struct.pack('>B', len(label)))
            body.append(label)
        body.append(struct.pack('>B', 0))
        body.append(struct.pack('>H', self.qtypes[r_type]))
        body.append(struct.pack('>H', 1))
        return b''.join(body)


class DnsResponseParser:
    qtypes = {
        1: 'A',
        28: 'AAAA',
        15: 'MX',
        2: 'NS'
    }
    flags = [('QR', 1), ('Opcode', 4), ('AA', 1), ('TC', 1),
             ('RD', 1), ('RA', 1), ('Z', 3), ('RCODE', 4)]

    def parse_response(self, response):
        result = {'header': self.__parse_header__(response[:12])}
        result['body'] = self.__parse_body__(response[12:], result['header'])
        return result

    def __parse_header__(self, header):
        result = {}
        id, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", header)
        result['id'] = id
        for i in range(len(self.flags) - 1, -1, -1):
            result[self.flags[i][0]] = flags % 2 ** self.flags[i][1]
            flags //= 2 ** self.flags[i][1]
        result['qdcount'] = qd
        result['ancount'] = an
        result['nscount'] = ns
        result['arcount'] = ar
        return result

    def __parse_body__(self, data, header):
        result = {}
        sections = {
            'question': header['qdcount'],
            'answer': header['ancount'],
            'authority': header['nscount'],
            'additional': header['arcount']
        }
        cursor = 0
        for section in sections:
            for i in range(sections[section]):
                if section not in result:
                    result[section] = []
                sec, cursor = self.__parse_record__(data, cursor)
                result[section].append(sec)
        return result

    def __get_question_section__(self, data, cursor):
        section = {}
        section['name'], cursor = self.__read_name__(data, cursor)
        cursor += 1
        section['type'] = self.qtypes[struct.unpack('>H', data[cursor: cursor + 2])[0]]
        cursor += 2
        section['class'] = struct.unpack('>H', data[cursor: cursor + 2])[0]
        cursor += 2
        return section, cursor

    def __parse_record__(self, data: bytes, cursor: int):
        record = {}
        if data[cursor] == 192:
            start_index = data[cursor + 1] - 12
            record['name'], _ = self.__read_name__(data, start_index)
            cursor += 2
            record['type'] = struct.unpack('>H', data[cursor: cursor + 2])[0]
            cursor += 2
            record['class'] = struct.unpack('>H', data[cursor: cursor + 2])[0]
            cursor += 2
            record['ttl'] = struct.unpack('>I', data[cursor: cursor + 4])[0]
            cursor += 4
            size = struct.unpack('>H', data[cursor: cursor + 2])[0]
            cursor += 2
            record['data'] = self.__parse_data__(data, cursor, size, record['type'])
            cursor += size
            return record, cursor
        return self.__get_question_section__(data, cursor)

    def __read_name__(self, data, cursor, size=0):
        name = []
        end_index = cursor + size
        while data[cursor] != 0 and (not size or cursor < end_index):
            if data[cursor] == 192:
                name_size = data[cursor + 1]
                label, _ = self.__read_name__(data, name_size - 12)
                name.append(label)
                cursor += 2
                break
            label_size = data[cursor]
            label = data[cursor + 1: cursor + label_size + 1].decode()
            name.append(label)
            cursor += label_size + 1
        return '.'.join(name), cursor

    def __parse_ip__(self, data, cursor, size):
        return str(ipaddress.IPv4Address(data[cursor: cursor + size]))

    def __parse_ipv6__(self, data, cursor, size):
        return str(ipaddress.IPv6Address(data[cursor: cursor + size]))

    def __parse_mx__(self, data, cursor, size):
        preference = struct.unpack('>H', data[cursor: cursor + 2])[0]
        mail_exchange, _ = self.__read_name__(data, cursor + 2, size - 2)
        return ' '.join([str(preference), mail_exchange])

    def __parse_data__(self, data, cursor, size, type_code):
        if type_code == 2:
            return self.__read_name__(data, cursor, size)[0]
        elif type_code == 1:
            return self.__parse_ip__(data, cursor, size)
        elif type_code == 28:
            return self.__parse_ipv6__(data, cursor, size)
        elif type_code == 15:
            return self.__parse_mx__(data, cursor, size)
