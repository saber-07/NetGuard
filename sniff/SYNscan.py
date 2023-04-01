from scapy.all import *

def detect_port_scan(pkt):  # sourcery skip: extract-method, last-if-guard
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        # Extraire les adresses IP source et destination, ainsi que les ports source et destination
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        # Envoyer une réponse SYN/ACK pour compléter le handshake TCP
        response_pkt = IP(dst=src_ip)/TCP(dport=sport, sport=dport, flags="SA")
        send(response_pkt, verbose=0)
        # Attendre qu'un drapeau ACK soit envoyé
        ack_pkt = sniff(filter=f"tcp and src host {src_ip} and dst host {dst_ip} and src port {sport} and dst port {dport} and tcp[13] & 16 != 0", timeout=2)
        if len(ack_pkt) == 0:
            # Si aucun drapeau ACK n'est reçu, indiquer qu'un scan TCP SYN a été détecté
            print(f"Scan TCP SYN détecté de {src_ip} à {dst_ip} sur le port {dport}")
            # Ou prendre toute autre mesure, comme journaliser l'événement, bloquer l'IP, etc.
        else:
            # Si un drapeau ACK est reçu, indiquer qu'une connexion légitime a peut-être été établie
            print(f"Paquet reçu après SYN/ACK de {src_ip} à {dst_ip} sur le port {dport}, connexion légitime possible")

# Capturer les paquets TCP 
sniff(filter="tcp ", prn=detect_port_scan)
