import os
import sys
import argparse
from sniff import SSHAnalyser, ICMPspoofing, ARPspoofing, SmurfAttack, SYNscan, mailCredantials, ipClassification, PortScan, PortScanning

def main():
    if os.geteuid() != 0:
        print('Warning: this script requires root privileges', file=sys.stderr)
    parser = argparse.ArgumentParser(description='Hello')

    parser.add_argument("sniffer", choices=["ssh","icmp","arp","smurf","syn","mail","ip","pscan","pscanning"],
                        help="which sniffer to use")


    args = parser.parse_args()



    if args.sniffer == "ssh":
        SSHAnalyser.sniff()

    elif args.sniffer == "icmp":
        ICMPspoofing.sniff()

    elif args.sniffer == "arp":
        ARPspoofing.sniff()

    elif args.sniffer == "smurf":
        SmurfAttack.sniff()

    elif args.sniffer == "syn":
        printf("syn")
        SYNscan.sniff()

    elif args.sniffer == "mail":
        mailCredantials.sniff()

    elif args.sniffer == "ip":
        ipClassification.sniff()

    elif args.sniffer == "pscan":
        PortScan.sniff()

    elif args.sniffer == "pscanning":
        PortScanning.sniff()




if __name__ == '__main__':
    main()
