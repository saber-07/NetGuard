from scapy.layers.inet import IP,TCP,Ether
from datetime import datetime,date


SSHPasswordAttempts = {}
SSHsuccess = {}
SSHLoginAttempts = {}
log = './log'

now = datetime.now()
today = datetime.today()
d2 = today.strftime("%B %d, %Y")
current_time=now.strftime("%H:%M:%S")

def SSHAnalysis(pkt):       #analyse les paquets ssh



    src = pkt[IP].src
    dst = pkt[IP].dst
    key = "dst:%s, src:%s" % (dst,src)
    dport = pkt[TCP].dport
    SSHLoginAttempts.setdefault(key, {})
    SSHLoginAttempts[key].setdefault(dst, 0)
    SSHPasswordAttempts.setdefault(key, {})
    SSHPasswordAttempts[key].setdefault(dport, 0)
    SSHsuccess.setdefault(key, {})
    SSHsuccess[key].setdefault(dport, 0)


    if pkt[IP].len in [73, 85] and dst in SSHLoginAttempts[key]:
        SSHLoginAttempts[key][dst] +=1
        print("%s Connection attempt from: \n IP:%s\n length:%s\n ethernet: %s\n" 
              % (SSHLoginAttempts[key][dst],pkt[IP].dst, pkt[IP].len + 14, pkt[Ether].src))


    if pkt[IP].len in [668,696] and dport in SSHsuccess[key]:  #paquets correspondant à la réussite de connexion
            SSHsuccess[key][dport] += 1
            print("\t\t.....................SSH success: %s\n" % SSHsuccess[key][dport])
            with open(log, 'a') as r:
                r.write(pkt[IP].dst) and r.write("\t-- Connection success\n")

    if pkt[IP].len in [116, 128, 136] and dport in SSHPasswordAttempts[key]:
        SSHPasswordAttempts[key][dport] += 1
            # eventuelles tentative de brute force
        with open(log, 'a') as r:
            r.write(pkt[IP].dst) and r.write("\t-- Connection success\n")

    if (SSHPasswordAttempts[key][dport] > 10 or SSHLoginAttempts[key][dst] > 10) and pkt[IP].len in [73, 85]:  # eventuelle tentative de brute force
        print("Potential brute forcing detected. \n")
        with open(log, 'a') as r:
            r.write("{}: ".format(d2)) and r.write(current_time) and r.write("\t-- Potential bruteforce detected\n")

    if pkt[IP].len in [128,88,192]: #Déconnexion
        SSHsuccess[key][dport] = 0
        SSHLoginAttempts[key][dst] = 0
