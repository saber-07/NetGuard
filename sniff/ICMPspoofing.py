from scapy.all import *


def detect_unsolicited_ping(packet):
    # Vérifie si le paquet reçu a l'adresse IP de destination du système local et contient le protocole ICMP
    if packet[IP].dst != my_ip or not packet.haslayer(ICMP):
        return
    
    # Calcule la longueur des données ICMP
    data_len = len(packet[ICMP].load) - 8
    print(data_len)
    
    # Si la longueur des données ICMP est de 32 ou 48 octets, cela signifie que c'est un paquet ICMP de taille normale, sinon, cela pourrait être une attaque de ping par lots.
    if data_len in [32, 48]:
        print(f"Large ICMP packet detected: {data_len} bytes from {packet[IP].src}")
    else:
        captured_icmp_packets = []
        
        # Vérifie si le paquet est une réponse à une demande de ping (type 0)
        if packet[ICMP].type == 0:
            # Récupère l'ID et la séquence de la demande de ping
            echo_request_id = packet[ICMP].id
            echo_request_seq = packet[ICMP].seq
            
            # Vérifie si aucune demande de ping n'a été enregistrée pour cette réponse ICMP
            if not any(packet.haslayer(ICMP) and
                       packet[ICMP].type == 8 and
                       packet[ICMP].id == echo_request_id and
                       packet[ICMP].seq == echo_request_seq
                       for packet in captured_icmp_packets):
                # Si aucune demande de ping correspondante n'a été trouvée, cela peut indiquer une attaque de ping non sollicité.
                print("Unsolicited ping detected from", packet[IP].src)

        # Si le paquet est une demande de ping, enregistre le paquet dans la liste des paquets capturés pour vérification future
        elif packet[ICMP].type == 8:
            captured_icmp_packets.append(packet)

# Commence la capture de paquets ICMP et appelle la fonction detect_unsolicited_ping pour chaque paquet capturé
sniff(filter="icmp", prn=detect_unsolicited_ping)

