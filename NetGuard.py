import click
from scapy.all import *
from sniff import ipClassification, PortScan


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


Netguard.add_command(ip_detector)
Netguard.add_command(port_scan_detector)

if __name__ == '__main__':
    Netguard()
