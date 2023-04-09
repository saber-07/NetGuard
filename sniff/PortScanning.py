from scapy.layers.inet import TCP,IP
import time

# Liste des signatures de scans de port à détecter
port_scan_signatures = {"S", "FPU", "NULL", "XMAS", "ACK"}

# Fonction de détection de scan de port
def detect_port_scan(pkt):
       if pkt.haslayer(TCP):
        # Vérifier si le drapeau TCP correspond à une signature de scan de port
        if pkt[TCP].flags in port_scan_signatures:
            # Vérifier si le port de destination est l'un des ports sensibles (21, 22, 23, 25, 80, 443)
            if pkt[TCP].dport in [21, 22, 23, 25, 80, 443]:
                # Attendre 1 seconde pour permettre à d'autres paquets de compléter un éventuel handshake TCP
                time.sleep(1)

                # Vérifier si le paquet a une charge utile TCP vide et une fenêtre TCP de 8192 octets
                if len(pkt[TCP].payload) == 0 and pkt[TCP].window == 8192:
                    # Afficher un message indiquant qu'un scan de port a été détecté
                    print(f"Scan de port détecté depuis {pkt[IP].src}:{pkt[TCP].sport}")
                    with open("./log",'a') as r:
                        r.write("Scan de port détecté depuis {}:{}\n".format(pkt[IP].src,pkt[TCP].sport))

    
    
    
    
    # Vérifier si le paquet contient une couche TCP et si le drapeau TCP correspond à une signature de scan de port
    # if (pkt.haslayer(TCP) and pkt[TCP].flags in port_scan_signatures
    #     # Vérifier si le port de destination est l'un des ports sensibles (21, 22, 23, 25, 80, 443)
    #     and pkt[TCP].dport in [21, 22, 23, 25, 80, 443]):
        
    #     # Attendre 1 seconde pour permettre à d'autres paquets de compléter un éventuel handshake TCP
    #     time.sleep(1)
        
    #     # Vérifier si le paquet a une charge utile TCP vide et une fenêtre TCP de 8192 octets
    #     if len(pkt[TCP].payload) == 0 and pkt[TCP].window == 8192:
    #         # Afficher un message indiquant qu'un scan de port a été détecté
    #         print(f"Scan de port détecté depuis {pkt[IP].src}:{pkt[TCP].sport}")
    #         with open("./log",'a') as r:
    #             r.write("Scan de port détecté depuis {}:{}".format(pkt[IP].src,pkt[TCP].sport))
