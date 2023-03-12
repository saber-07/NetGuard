from scapy.all import *

my_ip = "192.168.0.16"
interface = "wlan0"


def is_ping_packet(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        return True
    else:
        return False


def is_broadcast_packet(packet):
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    if packet.haslayer(Ether) and packet[Ether].dst == broadcast_mac:
        return True
    else:
        return False


def is_smurf_packet(packet):
    if is_ping_packet(packet) and is_broadcast_packet(packet):
        return True
    else:
        return False


def detect_smurf_attack(packet):
    print(packet[IP].src)
    # Check if the packet is a Smurf attack packet targeting your IP address
    if is_smurf_packet(packet) and packet[IP].dst == my_ip:
        print("Smurf attack detected targeting your IP address!")


sniff(iface=interface, filter="ip", prn=detect_smurf_attack)
