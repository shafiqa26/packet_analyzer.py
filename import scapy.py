
from scapy.all import sniff, IP, TCP, UDP, Raw, conf

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        # Check for TCP layer
        if packet.haslayer(TCP):
            if packet.haslayer(Raw):  # Check if Raw layer exists
                try:
                    payload = packet[Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print("[*] TCP Payload:")
                    print(decoded_payload)
                except (IndexError, UnicodeDecodeError) as e:
                    print(f"Unable to decode TCP payload: {e}")
        
        # Check for UDP layer
        elif packet.haslayer(UDP):
            if packet.haslayer(Raw):  # Check if Raw layer exists
                try:
                    payload = packet[Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print("[*] UDP Payload:")
                    print(decoded_payload)
                except (IndexError, UnicodeDecodeError) as e:
                    print(f"Unable to decode UDP payload: {e}")

def start_sniffing():
    print("Starting packet sniffing...")
    conf.l3socket = conf.L3socket  # Ensure you're using L3Socket
    sniff(prn=packet_callback, store=0)  # Sniffs packets and calls packet_callback for each

if __name__ == "__main__":  # Correct main entry point
    start_sniffing()




