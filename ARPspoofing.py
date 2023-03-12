from scapy.all import *
def detect_arp_spoof(pkt):
    # Check if the packet is an ARP reply
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        # Check if the MAC address of the sender matches the MAC address in our ARP cache
        if pkt[ARP].hwsrc != arp_cache[pkt[ARP].psrc]:
            print("ARP spoofing attack detected from MAC address {}".format(pkt[ARP].hwsrc))

# Get the MAC address of the local machine
local_mac = get_if_hwaddr("wlan0")

# Populate the ARP cache with the MAC addresses of all devices on the network
arp_cache = {}
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2, iface="eth0", inter=0.1)
for snd, rcv in ans:
    arp_cache[rcv[ARP].psrc] = rcv[ARP].hwsrc

# Start sniffing for ARP packets
sniff(filter="arp", prn=detect_arp_spoof)
