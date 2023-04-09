from scapy.all import *
import socket
import netifaces
from datetime import datetime,date




now = datetime.now()
today = datetime.today()
d2 = today.strftime("%B %d, %Y")
current_time=now.strftime("%H:%M:%S")


# Obtient les informations sur les interfaces réseau de la machine
interfaces = netifaces.interfaces()

# Parcourt les interfaces pour obtenir l'adresse IP de la première interface non locale
for interface in interfaces:
    if interface.startswith('lo'):
        continue
    addresses = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in addresses:
        my_ip = addresses[netifaces.AF_INET][0]['addr']
        break

log = './log'

def detect_unsolicited_ping(packet):
    # Vérifie si contient le protocole ICMP
    if not packet.haslayer(ICMP):
        return
    
    # Calcule la longueur des données ICMP
    data_len = len(packet[ICMP].load)
    
    # Si la longueur des données ICMP est de 32 ou 48 octets, cela signifie que c'est un paquet ICMP de taille normale, sinon, cela pourrait être une attaque de ping par lots.
    if data_len not in [32, 48, 56]:
        print(f"Large ICMP packet detected: {data_len} bytes from {packet[IP].src}")
        with open(log, 'a') as r:
            r.write("{}: ".format(d2)) and r.write(current_time) and r.write("Large ICMP packet detected: {} bytes from {}\n".format(data_len, packet[IP].src))    
    else:
        captured_icmp_packets = []

        # Si le paquet est une demande de ping, enregistre le paquet dans la liste des paquets capturés pour vérification future
        if packet[ICMP].type == 8:
            captured_icmp_packets.append(packet)

        # Vérifie si le paquet est une réponse à une demande de ping (type 0)
        elif packet[ICMP].type == 0:
            # Récupère l'ID et la séquence de la demande de ping
            echo_request_id = packet[ICMP].id
            echo_request_seq = packet[ICMP].seq

            if(packet[IP].src!=my_ip):
            
                # Vérifie si aucune demande de ping n'a été enregistrée pour cette réponse ICMP
                if not any(packet.haslayer(ICMP) and
                        packet[ICMP].type == 8 and
                        packet[ICMP].id == echo_request_id and
                        packet[ICMP].seq == echo_request_seq
                        for packet in captured_icmp_packets):
                    # Si aucune demande de ping correspondante n'a été trouvée, cela peut indiquer une attaque de ping non sollicité.
                    print("Unsolicited ping detected from", packet[IP].src)
                    with open(log, 'a') as r:
                       r.write("{}: ".format(d2)) and r.write(current_time) and r.write("Unsolicited ping detected from {}\n".format(packet[IP].src))    