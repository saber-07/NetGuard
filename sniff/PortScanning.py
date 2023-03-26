from scapy.all import *
import time

# Define the Nmap scan signatures
nmap_scan_signatures = ["S", "FPU", "NULL", "XMAS", "ACK"]

"""
This code checks if a TCP packet with an S flag is sent to a well-known port (e.g., FTP, SSH, Telnet, SMTP, HTTP, HTTPS) 
waits for a short period of time (1 second in this example) to see if more SYN packets are sent, and then checks if 
the packet matches the fingerprint of Nmap.
"""


def detect_nmap_scan(pkt):
    # Check if the packet is a TCP SYN packet
    if pkt.haslayer(TCP) and pkt[TCP].flags in nmap_scan_signatures:
        # Check if the packet is sent to a well-known port
        if pkt[TCP].dport in [21, 22, 23, 25, 80, 443]:
            # Wait for a short period of time to see if more SYN packets are sent
            time.sleep(1)
            if len(pkt[TCP].payload) == 0 and pkt[TCP].window == 8192:
                # The packet is likely sent by Nmap
                print("Nmap scan detected from %s:%s" % (pkt[IP].src, pkt[TCP].sport))


# Start sniffing packets
sniff(prn=detect_nmap_scan, filter="tcp")
