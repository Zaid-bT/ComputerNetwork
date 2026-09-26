import socket
import struct
import random


def encode_domain(domain):
    parts = domain.strip(".").split(".")
    encoded = b""

    for part in parts:
        encoded += struct.pack("B", len(part))
        encoded += part.encode()

    encoded += b"\x00"
    return encoded


def build_query(domain, transaction_id):
    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        0x0100,
        1,
        0,
        0,
        0
    )

    question = encode_domain(domain)

    question += struct.pack(
        "!HH",
        1,
        1
    )

    return header + question


def parse_domain_name(data, offset):
    labels = []
    original_offset = offset
    jumped = False

    while True:
        if offset >= len(data):
            raise ValueError("Malformed DNS name")

        length = data[offset]

        if length == 0:
            offset += 1
            break

        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Malformed DNS pointer")

            pointer = ((length & 0x3F) << 8) | data[offset + 1]

            if not jumped:
                original_offset = offset + 2

            offset = pointer
            jumped = True
            continue

        if length > 63:
            raise ValueError("Invalid DNS label length")

        offset += 1

        if offset + length > len(data):
            raise ValueError("Malformed DNS label")

        labels.append(
            data[offset:offset + length].decode("ascii", errors="replace")
        )

        offset += length

    name = ".".join(labels)

    if jumped:
        return name, original_offset

    return name, offset


def parse_response(data, transaction_id):
    if len(data) < 12:
        raise ValueError("DNS response is too short")

    (
        response_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount
    ) = struct.unpack("!HHHHHH", data[:12])

    if response_id != transaction_id:
        raise ValueError("Transaction ID mismatch")

    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0xF

    status = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED"
    }.get(rcode, f"UNKNOWN ({rcode})")

    offset = 12

    questions = []

    for _ in range(qdcount):
        name, offset = parse_domain_name(data, offset)

        if offset + 4 > len(data):
            raise ValueError("Malformed question section")

        qtype, qclass = struct.unpack(
            "!HH",
            data[offset:offset + 4]
        )

        offset += 4

        questions.append((name, qtype, qclass))

    answers = []

    for _ in range(ancount):
        name, offset = parse_domain_name(data, offset)

        if offset + 10 > len(data):
            raise ValueError("Malformed answer section")

        rtype, rclass, ttl, rdlength = struct.unpack(
            "!HHIH",
            data[offset:offset + 10]
        )

        offset += 10

        if offset + rdlength > len(data):
            raise ValueError("Malformed resource record")

        rdata = data[offset:offset + rdlength]
        offset += rdlength

        answer = {
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "data": rdata
        }

        if rtype == 1 and rdlength == 4:
            answer["ipv4"] = socket.inet_ntoa(rdata)

        answers.append(answer)

    return {
        "transaction_id": response_id,
        "flags": flags,
        "qr": qr,
        "opcode": opcode,
        "aa": aa,
        "tc": tc,
        "rd": rd,
        "ra": ra,
        "status": status,
        "questions": questions,
        "answers": answers,
        "authority_count": nscount,
        "additional_count": arcount
    }


def query_dns(domain, dns_server):
    transaction_id = random.randint(0, 65535)

    query = build_query(domain, transaction_id)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        sock.sendto(query, (dns_server, 53))

        response, server_address = sock.recvfrom(4096)

        result = parse_response(response, transaction_id)

        return result

    except socket.timeout:
        raise TimeoutError("DNS request timed out")

    finally:
        sock.close()


def display_result(domain, dns_server, result):
    print("\n==========================================")
    print("DNS RESPONSE")
    print("==========================================")

    print(f"DNS Server       : {dns_server}")
    print(f"Query Name       : {domain}")
    print(f"Transaction ID   : {result['transaction_id']}")
    print(f"Response Status  : {result['status']}")

    print("\nFlags:")
    print(f"  QR (Response)  : {result['qr']}")
    print(f"  AA (Author.)   : {result['aa']}")
    print(f"  TC (Truncated) : {result['tc']}")
    print(f"  RD (Recursion) : {result['rd']}")
    print(f"  RA (Available) : {result['ra']}")

    print("\nQuestion Section:")

    for name, qtype, qclass in result["questions"]:
        type_name = {
            1: "A",
            2: "NS",
            5: "CNAME",
            28: "AAAA"
        }.get(qtype, str(qtype))

        print(f"  Name  : {name}")
        print(f"  Type  : {type_name}")
        print(f"  Class : {qclass}")

    print("\nAnswer Section:")

    if not result["answers"]:
        print("  No answer records found.")
    else:
        found_a = False

        for answer in result["answers"]:
            type_name = {
                1: "A",
                2: "NS",
                5: "CNAME",
                28: "AAAA"
            }.get(answer["type"], str(answer["type"]))

            print(f"  Name : {answer['name']}")
            print(f"  Type : {type_name}")
            print(f"  TTL  : {answer['ttl']} seconds")

            if answer["type"] == 1 and "ipv4" in answer:
                print(f"  IPv4 : {answer['ipv4']}")
                found_a = True

            print()

        if not found_a:
            print("No IPv4 A record was found.")


def main():
    print("==========================================")
    print("       UDP DNS QUERY PROGRAM")
    print("==========================================")

    dns_server = input("Enter DNS server IP: ").strip()

    while True:
        domain = input(
            "\nEnter domain name (or 'exit' to quit): "
        ).strip()

        if domain.lower() == "exit":
            print("Program terminated.")
            break

        if not domain:
            print("Error: Domain name cannot be empty.")
            continue

        try:
            result = query_dns(domain, dns_server)
            display_result(domain, dns_server, result)

        except TimeoutError as e:
            print(f"\nError: {e}")

        except ValueError as e:
            print(f"\nError: Invalid DNS response - {e}")

        except OSError as e:
            print(f"\nNetwork error: {e}")

        except Exception as e:
            print(f"\nUnexpected error: {e}")


if __name__ == "__main__":
    main()