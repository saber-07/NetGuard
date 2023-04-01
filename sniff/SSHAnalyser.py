from scapy.all import *
import json
SSHconnexions = {}
SSHattempts = {}
SSHsuccess = {}
SSHlogins = {}

def SSHAnalysis(pkt):       #analyse les paquets ssh

    src = pkt[IP].src
    dst = pkt[IP].dst
    key = "dst:%s, src:%s" % (dst,src)
    port = pkt[TCP].dport
    warning1 = "Login attempt"
    warning2 = "Certified IP, connection successful"
    warning3 = "Potential Brute Force, Malicious IP"

    if not key in SSHlogins:
        SSHlogins[key] = {}

    if not port in SSHlogins[key]:
        SSHlogins[key][port] = 0

        if pkt[IP].len == 87-14 or pkt[IP].len == 99-14:
            if port in SSHlogins[key]:
                SSHlogins[key][port] += 1

        print("Connection attempt from: \n IP:%s\n length:%s\n ethernet: %s\n" % (
            pkt[IP].src, pkt[IP].len + 14, pkt[Ether].src))


    if not key in SSHsuccess:   #paquets correspondant au succès de login
                SSHsuccess[key] = {}


    if not port in SSHsuccess[key]:
            SSHsuccess[key][port] = 0

    if pkt[IP].len == 682-14 or pkt[IP].len == 710 - 14:  #paquets correspondant à la réussite de connexion
            if port in SSHsuccess[key]:
                    SSHsuccess[key][port] += 1
            print("\t\t.....................SSH success: %s\n" % SSHsuccess[key][port])

if not key in SSHattempts:
        SSHattempts[key] = {}
    if not port in SSHattempts[key]:
        SSHattempts[key][port] = 0

    if pkt[IP].len == 130-14 or  pkt[IP].len == 150-14 or pkt[IP].len == 142 - 14:  #paquets correspondant aux aux interactions de login

            if port in SSHattempts[key]:
                SSHattempts[key][port] += 1

    if not key in SSHconnexions:
        SSHconnexions[key] = {}
    if not port in SSHattempts[key]:
        SSHconnexions[key][port]=0
    if port in SSHconnexions[key]:       #paquets correspondant à toutes les interactions du serveur ssh
            SSHconnexions[key][port] += 1

    if SSHattempts[key][port] > 10 and SSHsuccess[key][port] == 0:  # eventuelle tentative de brute force si + de 4 tentatives de connexion ET s'il n'y a pas eu de réussite
        print("Potential brute forcing detected. \n")

    if pkt[IP].len == 142-14 or pkt[IP].len == 102-14 or pkt[IP].len == 206 - 14: #Déconnexion
        print("\t\t..........DISCONNECT...........")
        SSHsuccess[key][port] = 0


    with open("listeIP.txt", "a") as file:  # dump les IPS dans un JSON

        if pkt[IP].len == 87 - 14 or 99-14:&
            json.dump({"src": src, "dst": dst}, file)
            json.dump({"warning": warning1}, file)
        elif pkt[IP].len == 682 - 14 or pkt[IP].len == 710 - 14:
            json.dump({"src": src, "dst": dst}, file)
            json.dump({"warning": warning2 }, file)
        elif SSHattempts[key][port] > 10 and SSHsuccess[key][port] == 0:
            json.dump({"src": src, "dst": dst}, file)
            json.dump({"warning": warning3}, file)
        file.write("\n")


def analyzePkt(pkt):

    if pkt.haslayer(TCP) and pkt[TCP].sport == 22:      #on filtre uniquement sur le port ssh
        SSHAnalysis(pkt)
        if pkt[IP].len == 682-14 or pkt[IP].len == 710-14:
            print(" \t\t............Connection Established.............\n")


sniff(filter="tcp", prn=analyzePkt, count=0)

