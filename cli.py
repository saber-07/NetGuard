import argparse
import subprocess
import sys

def main():

    parser = argparse.ArgumentParser(description='Hello')

    parser.add_argument("--sniffer", choices=["ssh","icmp","arp","smurf","syn","mail","ip","pscan","pscanning"],     help="which sniffer to use")

    args = parser.parse_args()
    print("processus en cours:")
    try:
        if args.sniffer == "ssh":
            if sys.platform.startswith('win'):
                subprocess.Popen(["py", "./sniff/SSHAnalyser.py"])
            elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                subprocess.Popen(["python3", "./sniff/SSHAnalyser.py"])
        elif args.sniffer == "icmp":
            if sys.platform.startswith('win'):
                subprocess.Popen(["py", "./sniff/ICMPspoofing.py"])
            elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                subprocess.Popen(["python3", "./sniff/ICMPspoofing.py"])
        elif args.sniffer == "arp":
            if sys.platform.startswith('win'):
                subprocess.Popen(["py", "./sniff/ARPspoofing.py"])
            elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                subprocess.Popen(["python3", "./sniff/ARPspoofing.py"])
        elif args.sniffer == "smurf":
            if sys.platform.startswith('win'):
                subprocess.Popen(["py", "./sniff/SmurfAttack.py"])
            elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                subprocess.Popen(["python3", "./sniff/SmurfAttack.py"])
        elif args.sniffer == "syn":
            if sys.platform.startswith('win'):
                subprocess.Popen(["py", "./sniff/SYNscan.py"])
            elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                subprocess.Popen(["python3", "./sniff/SYNscan.py"])
        elif args.sniffer == "mail":
            if sys.platform.startswith('win'):
                subprocess.Popen(["py", "./sniff/mailCredantials.py"])
            elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                subprocess.Popen(["python3", "./sniff/mailCredantials.py"])
        elif args.sniffer == "ip":
            if sys.platform.startswith('win'):
                subprocess.Popen(["py", "./sniff/ipClassification.py"])
            elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                subprocess.Popen(["python3", "./sniff/ipClassification.py"])
        elif args.sniffer == "pscan":
            if sys.platform.startswith('win'):
                subprocess.Popen(["py", "./sniff/PortScan.py"])
            elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                subprocess.Popen(["python3", "./sniff/PortScan.py"])
        elif args.sniffer == "pscanning":
            if sys.platform.startswith('win'):
                subprocess.Popen(["py", "./sniff/PortScanning.py"])
            elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                subprocess.Popen(["python3", "./sniff/PortScanning.py"])
        else:
            print("programme inconnu")
    except KeyboardInterrupt:
        subprocess.Popen.kill()
        parser.exit(0,"terminé")

if __name__ == '__main__':
    main()


