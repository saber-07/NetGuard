import click
from scapy.all import *
from sniff import ipClassification, PortScan, ARPspoofing, SSHAnalyser, ICMPspoofing, PortScanning, SYNscan, SmurfAttack


@click.group()
def Netguard():
    pass


@Netguard.command()
def ip_detector():
    print("Starting packet sniffer...")
    sniff(filter="ip", prn=ipClassification.packet_callback)


@Netguard.command()
def port_scan_detector():
    print("Checking for port scans...")
    while True:
        sniff(prn=PortScan.packet_callback, filter="tcp", store=0, timeout=PortScan.time_window)
        PortScan.check_port_scan()
        time.sleep(PortScan.time_window)

@Netguard.command()
def arp_spoofing_detector():
    try:
        print("[*] Démarrage de la détection de spoofing ARP")
        sniff(filter="arp", prn=ARPspoofing.arp_display, store=0, count=0)
        # Capturer les paquets ARP
    except KeyboardInterrupt:
        print("[*] Arrêt de la détection de spoofing ARP")
        exit(0)

@Netguard.command()
def icmp_spoofing():
    # Commence la capture de paquets ICMP et appelle la fonction detect_unsolicited_ping pour chaque paquet capturé
        print("Démarrage de la détection ICMP")
        sniff(filter="icmp",prn=ICMPspoofing.detect_unsolicited_ping)

@Netguard.command()
def ssh_brut_force_detector():
    print("Checking for SSH brute force attack...")
    sniff(filter="ip",prn=SSHAnalyser.SSHAnalysis)



@Netguard.command()
def port_scanning():
    print("Checking for Port Scanning...")
    sniff(prn=PortScanning.detect_port_scan, filter="tcp")

@Netguard.command()
def syn_scan():
    print("Checking for Port Scanning...")
    sniff(prn=SYNscan.detect_port_scan, filter="tcp")

@Netguard.command()
def Smurf_Attack_detector():
    print("Checking for posible smurf attack...")
    # Sniffe les paquets ICMP et appelle la fonction detect_smurf_attack pour chaque paquet reçu
    sniff(filter="icmp", prn=SmurfAttack.detect_smurf_attack)


Netguard.add_command(ip_detector)
Netguard.add_command(port_scan_detector)
Netguard.add_command(ssh_brut_force_detector)
Netguard.add_command(arp_spoofing_detector)
Netguard.add_command(port_scanning)
Netguard.add_command(syn_scan)
Netguard.add_command(Smurf_Attack_detector)
Netguard.add_command(icmp_spoofing)

if __name__ == '__main__':
    Netguard()
