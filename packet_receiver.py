import socket
import struct

def calculate_checksum(data):
    if len(data) % 2 != 0:
        data += b'\0'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    return ~s & 0xffff

def main():
    expected_source_ip = '192.168.0.3'
    expected_payload_start = b"COLOMBIA 2 - MESSI 0"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) as s:
            s.bind(('0.0.0.0', 0))
            print("Socket successfully created and bound to 0.0.0.0")

            # Include this line to allow the socket to capture IP headers
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            while True:
                packet, addr = s.recvfrom(65565)
                ip_header = packet[:20]
                data = packet[20:]

                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                checksum = iph[7]

                header = struct.pack('!BBHHHBBH4s4s', iph[0], iph[1], iph[2], iph[3], iph[4], iph[5], iph[6], 0, iph[8], iph[9])
                calculated_checksum = calculate_checksum(header)

                if calculated_checksum == checksum:
                    src_ip = socket.inet_ntoa(iph[8])
                    if src_ip == expected_source_ip and data.startswith(expected_payload_start):
                        try:
                            payload = data.decode('utf-8')
                            print(f"Received data from {addr[0]}: {payload}")
                            print("The verification of the checksum demonstrates that the packet received is correct.")
                        except UnicodeDecodeError:
                            print(f"Received data from {addr[0]}: {data}")
                            print("The verification of the checksum demonstrates that the packet received is correct, but the payload is not UTF-8.")
                    else:
                        print(f"Ignored packet from {addr[0]} with unexpected data.")
                else:
                    print("The verification of the checksum demonstrates that the packet received is corrupted. Packet discarded!")

    except PermissionError as e:
        print(f"Permission error: {e}. Please run the script with administrative privileges.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
