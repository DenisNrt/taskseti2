import socket
import struct
import random
import threading
import time
import cache

HOST = "localhost"
PORT = 53
ROOT_SERVERS = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "192.58.128.30"
]


def extract_question_domain(data):
    offset = 12
    parts = []
    while data[offset] != 0:
        length = data[offset]
        offset += 1
        parts.append(data[offset:offset + length].decode("ascii"))
        offset += length
    offset += 1
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    offset += 4
    return ".".join(parts).lower(), qtype, qclass, offset


def skip_domain(current_offset, additional_section):
    while True:
        length = additional_section[current_offset]
        if length == 0:
            # конец домена
            return current_offset + 1
        elif (length & 0xC0) == 0xC0:
            # маркер сжатия (указатель). Он занимает ровно 2 байта
            # и ВСЕГДА означает конец имени в этой записи
            return current_offset + 2
        else:
            # сдвигаем на длину части домена + байт, где длина
            current_offset += 1 + length


def get_next_ip(additional_section, qdcount, ancount, nscount, arcount):
    try:
        offset = 12
        # скипаем секцию question
        for _ in range(qdcount):
            offset = skip_domain(offset, additional_section) + 4
        # скипаем answer и authority
        for _ in range(ancount + nscount):
            offset = skip_domain(offset, additional_section) + 8
            offset += 2 + int.from_bytes(additional_section[offset:offset + 2], 'big')
        # читаем и ищем ipv4 адрес
        for _ in range(arcount):
            offset = skip_domain(offset, additional_section)
            record_type = int.from_bytes(additional_section[offset:offset + 2], 'big')

            offset += 8
            rdlength = int.from_bytes(additional_section[offset:offset + 2], 'big')
            offset += 2

            # Если это ipv4 адрес (А-запись)
            if record_type == 1 and rdlength == 4:
                ip_bytes = additional_section[offset:offset + 4]
                return socket.inet_ntoa(ip_bytes)
            offset += rdlength
        return None
    except Exception:
        return None


def set_ra_flag(data):
    ## устанавливает флаг Recursion Available
    p = bytearray(data)
    p[3] |= 0x80
    return bytes(p)


def build_multiply_response(request_data, domain, end_offset):
    try:
        prefix = domain.split('.multiply.')[0]
        nums = [int(x) for x in prefix.split('.')]
        res = 1
        for n in nums:
            res = (res * n) % 256
        ip = f"127.0.0.{res}"
    except Exception:
        ip = "127.0.0.0"
    tid = request_data[:2]
    flags = struct.pack("!H", 0x8180)
    counts = struct.pack("!HHHH", 1, 1, 0, 0)
    header = tid + flags + counts

    question = request_data[12:end_offset]

    # маркер сжатия (указатель на 12-й байт пакета, где лежит оригинальное имя)
    name_pointer = struct.pack("!H", 0xC00C)
    # type A (1), Class IN (1), TTL, RDLENGTH (4 байта для ipv4)
    rr_header = struct.pack("!HHLH", 1, 1, 300, 4)
    # Превращаем строку с ip в 4 сырых
    rdata = socket.inet_aton(ip)

    return header + question + name_pointer + rr_header + rdata


def extract_ttl(response_data, qdcount):
    try:
        offset = 12
        # пропускаем вопросы
        for _ in range(qdcount):
            offset = skip_domain(offset, response_data) + 4
        # скипаем имя, тип и класс ответа
        offset = skip_domain(offset, response_data)
        offset += 4

        # читаем ttl
        ttl = int.from_bytes(response_data[offset:offset + 4], 'big')
        return ttl
    except Exception:
        return 300


def resolve_iteratively(client_request_data):
    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', client_request_data[:12])
    if qdcount == 0:
        return None
    domain, qtype, qclass, end_domain_offset = extract_question_domain(client_request_data)

    if ".multiply." in domain:
        return build_multiply_response(client_request_data, domain, end_domain_offset)

    cached_data = cache.get_from_cache(domain, qtype)
    if cached_data:
        # меняем id и отправляем из кэша
        res = bytearray(cached_data)
        res[:2] = client_request_data[:2]
        return bytes(res)

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.settimeout(3.0)
    current_target_ip = random.choice(ROOT_SERVERS)
    for i in range(50):
        try:
            client_sock.sendto(client_request_data, (current_target_ip, PORT))
            response_data, _ = client_sock.recvfrom(4096)
            tid, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', response_data[:12])
            rcode = flags & 0x000F  # код ответа

            if rcode in (2, 3):  # 2 - NXDOMAIN, 3 - SERVFAIL
                return set_ra_flag(response_data)

            if ancount > 0:
                final_response = set_ra_flag(response_data)
                # ttl вытаскиваем из ответа
                ttl = extract_ttl(final_response, qdcount)
                cache.add_to_cache(domain, qtype, ttl, final_response)
                return final_response
            elif nscount > 0:
                next_ip = get_next_ip(response_data, qdcount, ancount, nscount, arcount)
                if next_ip:
                    current_target_ip = next_ip
                    continue
                else:
                    return set_ra_flag(response_data)
            else:
                return set_ra_flag(response_data)
        except socket.timeout:
            print(f"Таймаут при запросе к {current_target_ip}")
            break
    return None


def handle_udp_client(data, addr, sock):
    response = resolve_iteratively(data)
    if response:
        sock.sendto(response, addr)


## По UDP слушаем 127.0.0.1:53
def udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"Слушаю UDP {HOST}:{PORT}")
    while True:
        data, addr = sock.recvfrom(512)
        if len(data) < 12:
            continue
        threading.Thread(target=handle_udp_client, args=(data, addr, sock), daemon=True).start()


## По TCP слушаем 127.0.0.1:53
def tcp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"Слушаю TCP {HOST}:{PORT}")
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_tcp_client, args=(conn,), daemon=True).start()


def handle_tcp_client(conn):
    with conn:
        try:
            # TCP DNS запросы начинаются с 2 байт длины
            length_bytes = conn.recv(2)
            if not length_bytes or len(length_bytes) != 2:
                return
            length = struct.unpack("!H", length_bytes)[0]
            data = conn.recv(length)

            response = resolve_iteratively(data)
            if response:
                # Ответ тоже начинается с 2 байт длины
                conn.sendall(struct.pack("!H", len(response)) + response)
        except Exception:
            pass


if __name__ == "__main__":
    cache.load_cache()
    threading.Thread(target=udp_server, daemon=True).start()
    threading.Thread(target=tcp_server, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cache.save_cache()
