from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    print("\n--- New Packet Captured ---")

    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Check for TCP
        if TCP in packet:
            tcp_layer = packet[TCP]
            print("Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Payload: {bytes(tcp_layer.payload)}")

        # Check for UDP
        elif UDP in packet:
            udp_layer = packet[UDP]
            print("Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print(f"Payload: {bytes(udp_layer.payload)}")

        # Check for ICMP
        elif ICMP in packet:
            print("Protocol: ICMP")
            icmp_layer = packet[ICMP]
            print(f"Type: {icmp_layer.type}")
            print(f"Code: {icmp_layer.code}")
            print(f"Payload: {bytes(icmp_layer.payload)}")

        else:
            print("Other IP Protocol")
            print(f"Payload: {bytes(ip_layer.payload)}")

    else:
        print("Non-IP Packet")
        print(packet.summary())

def main():
    print("Starting packet capture... Press Ctrl+C to stop.")
    # Capture packets indefinitely, applying the callback function on each packet
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
