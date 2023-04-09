from scapy.all import *
from datetime import datetime,date




now = datetime.now()
today = datetime.today()
d2 = today.strftime("%B %d, %Y")
current_time=now.strftime("%H:%M:%S")

log = './log'

# La fonction is_ping_packet retourne vrai si le paquet ICMP est de type ping (type 8)
def is_ping_packet(packet):
    return bool(packet.haslayer(ICMP) and packet[ICMP].type == 8)

# La fonction is_broadcast_packet retourne vrai si l'adresse MAC de destination du paquet est l'adresse de broadcast (ff:ff:ff:ff:ff:ff)
def is_broadcast_packet(packet):
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    return bool(packet.haslayer(Ether) and packet[Ether].dst == broadcast_mac)

# La fonction detect_smurf_attack affiche l'adresse IP source du paquet si c'est un paquet ICMP de type ping
# qui est envoyé à une adresse MAC de broadcast, ce qui est caractéristique d'une attaque Smurf
def detect_smurf_attack(packet):
    if is_ping_packet(packet) and is_broadcast_packet(packet):
        print("Smurf attack detected from", packet[IP].src)
        with open(log,'a') as r:
            r.write("{}: ".format(d2)) and r.write(current_time) and r.write(" \nSmurf attack detected from:") and r.write(packet[IP].src)
