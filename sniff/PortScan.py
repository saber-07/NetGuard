from scapy.all import *
import time

# Define the list of common ports to scan
common_ports = [21, 22, 23, 25, 80, 443]

# Define the list of TCP flags used in port scanning
port_scan_signatures = ["S", "A", "F", "FPU", ""]

# Initialize a dictionary to keep track of the number of connections to each port
port_counts = {port: 0 for port in common_ports}

# Define the time window (in seconds) between successive port scan checks
time_window = 10

# Define a function to check for port scans
def check_port_scan():
    print(f"Checking for port scans at {time.ctime()}")

    # Check the port counts for each common port
    for port in common_ports:
        if port_counts[port] > 3:
            print(f"Possible port scanning detected on port {port}!")
            with open("../log", 'a') as r:
                r.write(f"Possible port scanning detected on port {port}!")

    # Reset the port counts
    port_counts.clear()
    port_counts.update({port: 0 for port in common_ports})

# Define a function to process each packet in the captured traffic
def packet_callback(packet):
    # Check if the packet is a TCP packet with a SYN, ACK, FIN, URG, or PSH flag set
    if (
            TCP in packet
            and packet[TCP].flags in port_scan_signatures
            and packet[TCP].dport in common_ports):
        # Increment the count for this port
        port_counts[packet[TCP].dport] += 1

