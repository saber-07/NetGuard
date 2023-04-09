from scapy.all import *
import json
import requests
import time

LOG = '../resultat.txt'
ips = []
interface = "wlan0"
api_key = "24f96dafeb29ade43f5b57f2bd860e72152432a610a8f7b4059213059893802f"
# my_ip = "93.6.139.189"


def packet_callback(packet):
    # sourcery skip: extract-method, last-if-guard, use-fstring-for-formatting
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if not src_ip.startswith("10.") and not src_ip.startswith("172.") and not src_ip.startswith("192.168") :
            print(packet[IP].src)
            ip = packet[IP].src
            # Construct the request URL
            url = "https://www.virustotal.com/api/v3/ip_addresses/{}".format(ip)

            # Add the API key to the headers
            headers = {
                "x-apikey": api_key
            }

            # Send the GET request
            response = requests.get(url, headers=headers)

            # Parse the response as JSON
            data = json.loads(response.text)

            # Check if the IP address is considered malicious
            if data["data"]["attributes"]["last_analysis_stats"]["malicious"] == 0 and data["data"]["attributes"]["last_analysis_stats"]["suspicious"] == 0:
                with open(LOG, 'a') as r:
                    r.write(ip) and r.write(' --\twhite list\n')

            elif data["data"]["attributes"]["last_analysis_stats"]["malicious"] >= 0:
                with open(LOG, 'a') as r:
                    r.write(ip) and r.write(' --\tblack list\n')

            elif data["data"]["attributes"]["last_analysis_stats"]["suspicious"] >= 0:
                with open(LOG, 'a') as r:
                    r.write(ip) and r.write(' --\tgrey list\n')

            else:
                print("ip not found")

            # sleep 15 seconds to wait for the api response
            time.sleep(15)


sniff(filter="ip", prn=packet_callback)