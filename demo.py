"""
ethernet frame - destination(6), source(6), type(2), payload, CRC(4)
payload here is packet
IP packet - version(4), header length(4), type of service(8), total length(16), identification(16), flags(3), fragment offset(13), time to live(8), protocol(8), header checksum(16), source IP(32), destination IP(32), options, payload
and it then contains ip, furthur according to protocols it

| Format | C Type         | Python Type | Size |
| ------ | -------------- | ----------- | ---- |
| `b`    | signed char    | int         | 1    |
| `B`    | unsigned char  | int         | 1    |
| `h`    | short          | int         | 2    |
| `H`    | unsigned short | int         | 2    |
| `i`    | int            | int         | 4    |
| `I`    | unsigned int   | int         | 4    |
| `f`    | float          | float       | 4    |
| `d`    | double         | float       | 8    |
| `s`    | char[]         | bytes       | n    |

Byte Order
Use prefix in format string:
@ → native (default)
= → native std
< → little-endian
> → big-endian
! → network (big-endian) (most significant byte first)

struct.pack(format, values...): Python → bytes
struct.unpack(format, bytes): bytes → Python
"""

import struct
import socket

TAB_1 = ' ' * 4


DATA_TAB_1 = ' ' * 4


def ipv4Packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def main():
    #setting a raw IP socket on Windows
    HOST = socket.gethostbyname(socket.gethostname())   # Get the local IP address
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)  # RAW socket for IP packets
    conn.bind((HOST, 0))   # bind socket to ip address on port 0
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # tells os to include IP headers in the packets 
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # enables promiscuous mode to capture all packets

    try:
        while True:
            rawData, addr = conn.recvfrom(65535)  # buffer size of 65535 bytes
            version, header_length, ttl, proto, src, dest, payload = ipv4Packet(rawData)
            rawData, addr = conn.recvfrom(65535)
            version, header_length, ttl, proto, src, dest, payload = ipv4Packet(rawData)

            print(f"IPv4 Packet: {src} -> {dest}" + DATA_TAB_1 + f"Protocol: {proto}" + DATA_TAB_1 + f"TTL: {ttl}")

            if proto == 1:  # ICMP
                if len(payload) >= 4:
                    icmpType, code, checksum, data = icmpPacket(payload)
                    print(TAB_1 + f"ICMP Packet: Type={icmpType}" + DATA_TAB_1 + f"Code={code}" + DATA_TAB_1 + f"Checksum={checksum}" + DATA_TAB_1 + f"Data: {data}")
                else:
                    print(TAB_1 + "ICMP Packet too short")

            elif proto == 6:  # TCP
                if len(payload) >= 14:  # basic TCP header check
                    srcPort, destPort, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, data = tcpPacket(payload)
                    print(TAB_1 + f"TCP Packet: {src}:{srcPort} -> {dest}:{destPort}" + DATA_TAB_1 + 
                        f"Seq={seq}" + DATA_TAB_1 + f"Ack={ack}" + DATA_TAB_1 + 
                        f"Flags=URG:{flag_urg}, ACK:{flag_ack}, PSH:{flag_psh}, RST:{flag_rst}, SYN:{flag_syn}" + DATA_TAB_1 + f"DATA:{data}")
                else:
                    print(TAB_1 + "TCP Packet too short")

            elif proto == 17:  # UDP
                if len(payload) >= 8:
                    srcPort, destPort, length, data = udpPacket(payload)
                    print(TAB_1 + f"UDP Packet: {src}:{srcPort} -> {dest}:{destPort}" + DATA_TAB_1 + f"Length={length}" + DATA_TAB_1+ f"DATA:{data}")
                else:
                    print(TAB_1 + "UDP Packet too short")

            else:
                print(TAB_1 + f"Other Protocol: {proto}" + DATA_TAB_1 + f"Data Length: {len(payload)}")

    except KeyboardInterrupt:
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        conn.close()

# unpacking ICMP packets
def icmpPacket(data):
    icmpType, code, checksum = struct.unpack('! B B H', data[:4])
    return icmpType, code, checksum, data[4:]

# unpacking TCP packets
def tcpPacket(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4  # TCP header length in bytes

    flags = offset_reserved_flags & 0x3F
    flag_urg = (flags & 0x20)  # URG flag: defines if the urgent pointer field is significant, packet is urgent
    flag_ack = (flags & 0x10)  # ACK flag: defines if the acknowledgment field is significant, packet is an acknowledgment
    flag_psh = (flags & 0x08)  # PSH flag: defines if the receiver should pass the data to the application immediately, packet is push
    flag_rst = (flags & 0x04)  # RST flag: defines if the connection should be reset
    flag_syn = (flags & 0x02)  # SYN flag: defines if the connection is being established, packet is synchronized

    payload = data[offset:] if len(data) >= offset else b''  # slice correctly
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, payload


# unpacking UDP packets
def udpPacket(data):
    srcPort, destPort, length = struct.unpack('! H H H', data[:6])
    return srcPort, destPort, length, data[8:]

main()
