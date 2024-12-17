import scapy.all as scapy
import logging

# Setup logging
logging.basicConfig(filename='intrusion_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# define suspicious behaviors
SUSPICIOUS_PORTS = [22, 23, 80, 443]  # Example: SSH, Telnet, hTTP, HTTPS
SUSPICIOUS_IP_RANGES = ['192.168.1.1', '10.0.0.1']  # ex:internal network ranges
SUSPICIOUS_THRESHOLD = 10  # Threshold for too many packets from one IP

# Initialize dictionary to track packet counts
ip_counter = {}

# Function to analyze packet
def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst

        # Check for suspicious port (ex: common attack ports like 22, 23,)
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport in SUSPICIOUS_PORTS:
            logging.warning(f"Suspicious activity detected from {ip_src} to {ip_dst}: Port {packet[scapy.TCP].dport}")
        
        # Check for unusual destination IP (e.g, traffic to suspicious internal IP ranges)
        if ip_dst in SUSPICIOUS_IP_RANGES:
            logging.warning(f"Suspicious activity: {ip_src} targeting suspicious IP {ip_dst}")
        
        # Track packet count per source IP
        if ip_src not in ip_counter:
            ip_counter[ip_src] = 0
        ip_counter[ip_src] += 1

        # Check if a source IP is sending too many packets
        if ip_counter[ip_src] > SUSPICIOUS_THRESHOLD:
            logging.warning(f"Potential port scan detected from {ip_src} - Too many packets!")

# Function to start sniffing the network
def start_sniffing(interface="eth0"):
    print(f"[*] Starting packet capture on interface: {interface}")
    scapy.sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Start sniffing network traffic on a given interface (e.g., eth0)
    start_sniffing("eth0")  # replace "eth0" with network interface want to analyze
