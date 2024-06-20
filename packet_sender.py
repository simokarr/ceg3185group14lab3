import socket
import argparse
import struct

def calculate_checksum(data):
    if len(data) % 2 != 0:
        data += b'\0'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    return ~s & 0xffff

def create_ip_packet(data, src_ip, dest_ip):
    ihl_version = 45
    tos = 00
    tot_len = 20 + len(data)
    id = 54321
    frag_off = 4000
    ttl = 4006
    #protocol = socket.IPPROTO_TCP
    check = 0  # Initial checksum
    saddr = socket.inet_aton(src_ip)
    daddr = socket.inet_aton(dest_ip)

    header = struct.pack(ihl_version, tos, tot_len, id, frag_off, ttl, check, saddr, daddr)

    check = calculate_checksum(header)
    header = struct.pack(ihl_version, tos, tot_len, id, frag_off, ttl, check, saddr, daddr)

    return header + data

def main():
    parser = argparse.ArgumentParser(description="Packet sender")
    parser.add_argument('-server', type=str, required=True, help='Server IP address')
    parser.add_argument('-payload', type=str, required=True, help='Payload to send')

    args = parser.parse_args()
    server_ip = args.server
    payload = args.encode('utf-8')

    src_ip = '192.168.0.3'  # Example source IP
    packet = create_ip_packet(payload, src_ip, server_ip)
    print(packet)
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
        s.sendto(packet, (server_ip, 0))

if __name__ == "__main__":
    main()
