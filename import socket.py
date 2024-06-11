import sys

sys.path.append("C:/Users/Salma/Anaconda/Lib/site-packages")
import site
print(site.getsitepackages())

from scapy.all import *
import textwrap

# Constants 
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '




def packet(packet):
     if packet.haslayer(Ether):
        eth = packet.getlayer(Ether)
        print('\nEthernet Frame:')
        print(TAB_1 + f'Destination: {eth.dst}, Source: {eth.src}, Type: {eth.type}')

        if eth.type == 0x0800 and packet.haslayer(IP):  # IPv4
            ipv4_packet = packet.getlayer(IP)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + f'Version: {ipv4_packet.version}, Header Length: {ipv4_packet.ihl * 4}, TTL: {ipv4_packet.ttl}')
            print(TAB_2 + f'Protocol: {ipv4_packet.proto}, Source: {ipv4_packet.src}, Target: {ipv4_packet.dst}')

            if ipv4_packet.proto == 1 and packet.haslayer(ICMP):  # ICMP
                icmp_packet = packet.getlayer(ICMP)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + f'Type: {icmp_packet.type}, Code: {icmp_packet.code}, Checksum: {icmp_packet.chksum}')
                print(TAB_2 + 'Data:')
                print(format(DATA_TAB_3, bytes(icmp_packet.load) if hasattr(icmp_packet, 'load') else b''))

            elif ipv4_packet.proto == 6 and packet.haslayer(TCP):  # TCP
                tcp_packet = packet.getlayer(TCP)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + f'Source Port: {tcp_packet.sport}, Destination Port: {tcp_packet.dport}')
                print(TAB_2 + f'Sequence: {tcp_packet.seq}, Acknowledgement: {tcp_packet.ack}')
                print(TAB_2 + 'Flags:')
                print(TAB_3 + f'URG: {tcp_packet.flags & 0x20 >> 5}, ACK: {tcp_packet.flags & 0x10 >> 4}, PSH: {tcp_packet.flags & 0x08 >> 3}, RST: {tcp_packet.flags & 0x04 >> 2}, SYN: {tcp_packet.flags & 0x02 >> 1}, FIN: {tcp_packet.flags & 0x01}')
                print(TAB_2 + 'Data:')
                print(format(DATA_TAB_3, bytes(tcp_packet.payload) if hasattr(tcp_packet, 'payload') else b''))

            elif ipv4_packet.proto == 17 and packet.haslayer(UDP):  # UDP
                udp_packet = packet.getlayer(UDP)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + f'Source Port: {udp_packet.sport}, Destination Port: {udp_packet.dport}, Length: {udp_packet.len}')
                print(TAB_2 + 'Data:')
                print(format(DATA_TAB_3, bytes(udp_packet.payload) if hasattr(udp_packet, 'payload') else b''))

            else:  
                print(TAB_1 + 'Data:')
                print(format(DATA_TAB_2, bytes(ipv4_packet.payload) if hasattr(ipv4_packet, 'payload') else b''))

        else:  
            print('Data:')
            print(format(DATA_TAB_1, bytes(packet.payload) if hasattr(packet, 'payload') else b''))

def main():
    sniff(prn=packet, store=False)

def format(prefix, string, size=80):

    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == "__main__":
    main()