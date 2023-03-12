from scapy.all import *

def detect_port_scan(packet):
    if packet.haslayer(TCP):
        # Check if the TCP flags indicate a port scan
        if packet[TCP].flags == "FPU":
            print(f"Port scan detected from {packet[IP].src} to port {packet[TCP].dport}!")

sniff(iface="eth0", filter="tcp", prn=detect_port_scan)