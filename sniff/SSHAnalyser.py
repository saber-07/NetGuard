from scapy.all import *
import json
SSHconnexions = {}
SSHPasswordAttempts = {}
SSHsuccess = {}
SSHLoginAttempts = {}

def SSHAnalysis(pkt):       #analyse les paquets ssh

    src = pkt[IP].src
    dst = pkt[IP].dst
    key = "dst:%s, src:%s" % (dst,src)
    dport = pkt[TCP].dport
    warning1 = "Login attempt"
    warning2 = "Certified IP, connection successful"
    warning3 = "Potential Brute Force, Malicious IP"
    if not key in SSHLoginAttempts:
        SSHLoginAttempts[key] = {}

    if not dst in SSHLoginAttempts[key]:
        SSHLoginAttempts[key][dst] = 0

    if pkt[IP].len == 73 or pkt[IP].len == 85:
        SSHLoginAttempts[key][dst] +=1
        print("%s Connection attempt from: \n IP:%s\n length:%s\n ethernet: %s\n" % (SSHLoginAttempts[key][dst],pkt[IP].src, pkt[IP].len + 14, pkt[Ether].src))

    if not key in SSHsuccess:   #paquets correspondant au succès de login
                SSHsuccess[key] = {}


    if not dport in SSHsuccess[key]:
            SSHsuccess[key][dport] = 0

    if pkt[IP].len == 668 or pkt[IP].len == 696:  #paquets correspondant à la réussite de connexion
            if dport in SSHsuccess[key]:
                    SSHsuccess[key][dport] += 1
            print("\t\t.....................SSH success: %s\n" % SSHsuccess[key][dport])

    if not key in SSHPasswordAttempts: #crée le dictionnaire de clés de tentative
        SSHPasswordAttempts[key] = {}
    if not dport in SSHPasswordAttempts[key]:
        SSHPasswordAttempts[key][dport] = 0 #crée le dictionnaire de clés avec son port
        # paquets correspondant aux aux interactions de login
    if pkt[IP].len == 116 or  pkt[IP].len == 136 or pkt[IP].len == 128:
            if port in SSHPasswordAttempts[key]:
                SSHPasswordAttempts[key][dport] += 1
            # eventuelles tentative de brute force

    if (SSHPasswordAttempts[key][dport] > 10 or SSHLoginAttempts[key][dst] > 10) and SSHsuccess[key][dport] == 0:  # eventuelle tentative de brute force
        if pkt[IP].len == 73 or pkt[IP].len == 85:
            print("Potential brute forcing detected. \n")

    if not key in SSHconnexions: #compteur de paquets serveur du même port (connexion établie)
        SSHconnexions[key] = {}
    if not dport in SSHconnexions[key]:
        SSHconnexions[key][dport]=0
    if dport in SSHsuccess[key]:
        SSHconnexions[key][dport]+=1


    if pkt[IP].len == 128 or pkt[IP].len == 88 or pkt[IP].len == 192: #Déconnexion
        print("\t\t..........DISCONNECT...........\n")
        SSHsuccess[key][dport] = 0
        SSHLoginAttempts[key][dst] = 0



def analyzePkt(pkt):

    if pkt.haslayer(TCP) and pkt[TCP].sport == 22:      #on filtre uniquement sur le port ssh
        SSHAnalysis(pkt)
        if pkt[IP].len == 668 or pkt[IP].len == 696:
            print(" \t\t............Connection Established.............\n")


sniff(filter="tcp", prn=analyzePkt, count=0)
