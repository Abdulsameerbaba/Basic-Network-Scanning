# Import the scapy library
from scapy.all import sniff, IP, TCP, UDP

# This function will be called for each captured packet
def process_packet(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        
        # Default protocol and ports
        protocol = "Other"
        source_port = ""
        dest_port = ""

        # Check for TCP layer
        if packet.haslayer(TCP):
            protocol = "TCP"
            source_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            
        # Check for UDP layer
        elif packet.haslayer(UDP):
            protocol = "UDP"
            source_port = packet[UDP].sport
            dest_port = packet[UDP].dport
        
        # Print the extracted information
        print(f"[{protocol}] From {source_ip}:{source_port} -> To {destination_ip}:{dest_port}")

# Start sniffing
# count=10 means it will capture 10 packets and then stop.
# You can remove count to let it run indefinitely until you stop it (Ctrl+C).
print("Starting network sniffer...")
sniff(prn=process_packet, count=10)
print("Sniffer stopped.")