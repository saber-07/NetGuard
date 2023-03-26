import os
import sys
import argparse
from sniff import ICMPspoofing, ARPspoofing, ipClassification

def main():
    if os.geteuid() != 0:
        print('Warning: this script requires root privileges', file=sys.stderr)
    parser = argparse.ArgumentParser(description='')

    parser.add_argument("sniffer", choices=["sniffer1", "sniffer2", "sniffer3"],
                        help="which sniffer to use")
    args = parser.parse_args()

    if args.sniffer == "sniffer1":
        ICMPspoofing.sniff()
    elif args.sniffer == "sniffer2":
        ARPspoofing.sniff()
    elif args.sniffer == "sniffer3":
        ipClassification.sniff()
