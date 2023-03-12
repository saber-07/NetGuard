from scapy.all import *

my_ip = "192.168.0.16"
interface = "wlan0"


def detect_unsolicited_ping(packet):
    captured_icmp_packets = []

    if packet[IP].dst == my_ip and packet.haslayer(ICMP):
        data_len = len(packet[ICMP].load) - 8
        print(data_len)
        if data_len == 32 or data_len == 48:
            print(f"Large ICMP packet detected: {data_len} bytes from {packet[IP].src}")
        else:
            # Check if the packet is an ICMP echo reply
            if packet[ICMP].type == 0:
                # Check if there is no corresponding ICMP echo request
                echo_request_id = packet[ICMP].id
                echo_request_seq = packet[ICMP].seq
                if not any(packet.haslayer(ICMP) and
                           packet[ICMP].type == 8 and
                           packet[ICMP].id == echo_request_id and
                           packet[ICMP].seq == echo_request_seq
                           for packet in captured_icmp_packets):
                    print("Unsolicited ping detected from", packet[IP].src)

            elif packet[ICMP].type == 8:
                captured_icmp_packets.append(packet)


sniff(iface=interface, filter="icmp", prn=detect_unsolicited_ping)
