import socket
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

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
        s.bind(('0.0.0.0', 0))

        while True:
            packet, addr = s.recvfrom(65565)
            ip_header = packet[:20]
            data = packet[20:]

            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            checksum = iph[7]

            header = struct.pack('!BBHHHBBH4s4s', iph[0], iph[1], iph[2], iph[3], iph[4], iph[5], iph[6], 0, iph[8], iph[9])
            calculated_checksum = calculate_checksum(header)

            if calculated_checksum == checksum:
                print(f"Received data from {addr[0]}: {data.decode()}")
                print("The verification of the checksum demonstrates that the packet received is correct.")
            else:
                print("The verification of the checksum demonstrates that the packet received is corrupted. Packet discarded!")

if __name__ == "__main__":
    main()
