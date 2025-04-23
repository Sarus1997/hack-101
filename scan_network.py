from operator import ipow
from socket import IP_TOS, IP_TTL
from scapy.all import *

def sniff_packets(interface):
    print(f"Starting to sniff packets on {interface}")
    sniff(iface=interface, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(ipow):
        print(f"Packet from {packet[IP_TOS].src} to {packet[IP_TTL].dst} detected!")

sniff_packets("en0") 
