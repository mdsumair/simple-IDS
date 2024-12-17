import re
import scapy
from datetime import datetime
import logging

#setup logging
logging.basicConfig(file_name = "intrusion_log.txt", level=logging.INFO,format='%(asctime)s - %(message)s')

#define suspicious behaviour
suspicious_ports = [22,23,80,443]
suspicious_ip = ['192.168.1.1','10.0.0.1']
threshold = 30

#initializing dic to count packet
packet_count = {}

#function to analyze packet
def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

    #check for suspicious port
    if packet.haslayer(scapy.TCP) and packet[scapy.IP].dport in suspicious_ports:
        logging.warning(f"suspicious port detected {packet[scapy.IP].dport}")
    #suspicious ip 
    if dst_ip in suspicious_ip:
        logging.warning(f"ip detected from {src_ip} to {dst_ip}")
    #track packet count
    if src_ip not in packet_count:
        packet_count[src_ip] += 0
    packet_count[src_ip] += 1

    #Too many packets from same ip
    if packet_count[src_ip] > threshold:
        logging.warning(f"too many packets from {src_ip}")

    #function to start sniffing the network
def start_sniffing(interface="eth0"):
    print(f"started sniffing on {interface}")
    scapy.sniff(iface =interface,prn=packet_callback,store=0)

if __name__ == "__main__":
    start_sniffing("eth0")

