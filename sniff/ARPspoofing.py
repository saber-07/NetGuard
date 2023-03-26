from scapy.all import *


# turn off output
conf.verb = 0


def get_mac(ip_address):

    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)

    # return the MAC address from a response
    for s, r in responses:
        return r[Ether].src
    return None


def arp_display(pkt):
    if pkt[ARP].op == 2: # check if ARP response
        try:
            real_mac = get_mac(pkt[ARP].psrc) # get real MAC address
            response_mac = pkt[ARP].hwsrc # get MAC address from response
            if real_mac != response_mac:
                print(f"[!] Detected ARP spoofing from {response_mac} to {pkt[ARP].psrc}")
                # alert administrator here using email or other method
        except Exception as e:
            print(e)
            pass


try:
    print("[*] Starting ARP spoof detection")
    sniff(filter="arp", prn=arp_display, store=0, count=0)
    # sniff for ARP packets
except KeyboardInterrupt:
    print("[*] Exiting ARP spoof detection")
    exit(0)

