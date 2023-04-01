from scapy.all import *

# Définir l'adresse IP de l'hôte cible
target_host = "192.168.1.100"

# Définir une liste de ports courants à scanner
common_ports = [21, 22, 23, 25, 80, 443]

# Initialiser un dictionnaire pour suivre le nombre de connexions à chaque port
port_counts = {port: 0 for port in common_ports}

# Définir une fonction de rappel de paquet qui sera appelée pour chaque paquet dans le trafic capturé
def packet_callback(packet):
    # Vérifier si le paquet est un paquet TCP et a le drapeau SYN activé (c'est-à-dire, c'est un paquet SYN)
    if (
        TCP in packet
        and packet[TCP].flags == "S"
        and packet[IP].src == target_host
        and packet[TCP].dport in common_ports):
        # Incrémenter le compte pour ce port
        port_counts[packet[TCP].dport] += 1
        # Vérifier si ce port a eu plus de 3 connexions
        if port_counts[packet[TCP].dport] > 3:
            print(f"Possible port scanning detected from {target_host} to port {packet[TCP].dport}!")

# Capturer le trafic sur l'interface réseau pendant 60 secondes
# en appelant la fonction de rappel de paquet pour chaque paquet correspondant à notre filtre
sniff(prn=packet_callback, filter=f"src {target_host} and tcp", timeout=60)
