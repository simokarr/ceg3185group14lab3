import socket
import argparse
import struct

def calculate_checksum(header):
    checksum = 0
    for i in range(0, len(header), 2):
        word = (header[i] << 8) + (header[i + 1])
        checksum += word
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += (checksum >> 16)
    checksum = ~checksum & 0xFFFF
    return checksum

def create_ip_packet(data, src_ip, dest_ip):
    version = 4
    ihl = 5
    tos = 0
    tot_len = 20 + len(data)
    id = 54321
    frag_off = 0
    ttl = 64
    protocol = 6
    check = 0  # Initial checksum
    saddr = socket.inet_aton(src_ip)
    daddr = socket.inet_aton(dest_ip)

    ihl_version = (version << 4) + ihl
    header = struct.pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

    check = calculate_checksum(header)
    header = struct.pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

    return header + data

def main():
    parser = argparse.ArgumentParser(description="Packet sender")
    parser.add_argument('-server', type=str, required=True, help='Server IP address')
    parser.add_argument('-payload', type=str, required=True, help='Payload to send')

    args = parser.parse_args()
    server_ip = args.server
    payload = args.payload.encode()

    src_ip = '192.168.0.3'  # Example source IP
    packet = create_ip_packet(payload, src_ip, server_ip)

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
        s.sendto(packet, (server_ip, 0))

if __name__ == "__main__":
    main()
