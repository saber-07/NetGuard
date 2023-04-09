from scapy.all import *


# Désactiver la sortie de texte
conf.verb = 0

# Fonction pour obtenir l'adresse MAC associée à une adresse IP donnée
def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)

    # Récupérer l'adresse MAC depuis la réponse
    for s, r in responses:
        return r[Ether].src
    return None

# Fonction pour afficher les paquets ARP et détecter le spoofing ARP
def arp_display(pkt):
    if pkt[ARP].op == 2: # Vérifier si le paquet est une réponse ARP
        try:
            real_mac = get_mac(pkt[ARP].psrc) # Récupérer la véritable adresse MAC
            response_mac = pkt[ARP].hwsrc # Récupérer l'adresse MAC de la réponse
            if real_mac != response_mac:
                print(f"[!] Détection de spoofing ARP de {response_mac} à {pkt[ARP].psrc}")
                with open("./log", 'a') as r:
                    r.write("[!] Détection de spoofing ARP de {} à {}\n".format(response_mac,pkt[ARP].psrc))
                # Alerter l'administrateur ici en utilisant un e-mail ou autre méthode
        except Exception as e:
            print(e)

