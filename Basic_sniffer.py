import socket
import struct
import textwrap
from datetime import datetime

# Unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Format MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Format IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Format multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ' '.join(f'{b:02x}' for b in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Main function to capture and analyze packets
def main():
    # Create a raw socket
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        eth = ethernet_frame(raw_data)
        print(f'\nEthernet Frame: \nDestination: {eth[0]}, Source: {eth[1]}, Protocol: {eth[2]}')

        # IPv4 Packet
        if eth[2] == 8:
            ipv4_pkt = ipv4_packet(eth[3])
            print(f'\nIPv4 Packet: \nVersion: {ipv4_pkt[0]}, Header Length: {ipv4_pkt[1]}, TTL: {ipv4_pkt[2]}')
            print(f'Protocol: {ipv4_pkt[3]}, Source: {ipv4_pkt[4]}, Target: {ipv4_pkt[5]}')

            # ICMP
            if ipv4_pkt[3] == 1:
                icmp = icmp_packet(ipv4_pkt[6])
                print(f'\nICMP Packet: \nType: {icmp[0]}, Code: {icmp[1]}, Checksum: {icmp[2]}')
                print('\nData: {}'.format(format_multi_line("\t", icmp[3])))

            # TCP
            elif ipv4_pkt[3] == 6:
                tcp = tcp_segment(ipv4_pkt[6])
                print(f'\nTCP Segment: \nSource Port: {tcp[0]}, Destination Port: {tcp[1]}')
                print(f'Sequence: {tcp[2]}, Acknowledgment: {tcp[3]}')
                print(f'Flags: \nURG: {tcp[4]}, ACK: {tcp[5]}, PSH: {tcp[6]}, RST: {tcp[7]}, SYN: {tcp[8]}, FIN: {tcp[9]}')
                print('\nData: {}'.format(format_multi_line("\t", tcp[10])))

            # UDP
            elif ipv4_pkt[3] == 17:
                udp = udp_segment(ipv4_pkt[6])
                print(f'\nUDP Segment: \nSource Port: {udp[0]}, Destination Port: {udp[1]}, Length: {udp[2]}')

if __name__ == "__main__":
    main()
