
# ---  HELPER FUNCTION ---
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, IPv6


def print_details(packet_list):
    print(f"    > Analysis: Captured {len(packet_list)} packets.")
    
    for packet in packet_list:
        # Initialize variables
        src = "Unknown"
        dst = "Unknown"
        proto = "Unknown"
        
        # CASE 1: IPv4 Packet
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            
        # CASE 2: IPv6 Packet (The likely missing packets)
        elif packet.haslayer(IPv6):
            src = packet[IPv6].src
            dst = packet[IPv6].dst
            proto = packet[IPv6].nh # 'Next Header' is the protocol in IPv6

        # If we found an IP layer (v4 or v6), print the info
        if src != "Unknown":
            print(f"    [+] {src} -> {dst} | Protocol: {proto}")

            # Extract Payload

            # Check for Payload (Raw data)
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                try:
                    # Limit to first 50 chars to keep it clean
                    decoded = payload.decode('utf-8')
                    print(f"        Payload: {decoded[:50]}...") 
                except:
                    print(f"        Payload (Bytes): {payload[:20]}...")
            else:
                print("        Payload: Empty (Handshake or Encrypted)")
                
    print("-" * 50)

# ---------------------------

try:
    print("[*] Starting sniffer... ")

    # 1. ICMP Sniff
    print('\n1. Sniffing ICMP (Ping)... (Waiting for 5 packets)')
    # Tip: Open another terminal and type 'ping 8.8.8.8' to trigger this
    '''' send(IP(src = '192.168.187.128', dst = '8.8.8.8')/ICMP()/'HELLO WORLD') -use this to create a packet with a payload'''
    results = sniff(count=5, filter='icmp')
    print('   > Captured ICMP packets. Extracting data:')
    print_details(results) # <--- Calling our new function

    # 2. Port 80 Sniff
    print('\n2. Sniffing Port 80 (HTTP)... (Waiting for 5 packets)')
    print("   (Open a browser and visit 'http://example.com')")
    packets = sniff(filter="port 80", count=5) 
    print_details(packets) # <--- Calling our new function

    # 3. Port 443 Sniff
    print('\n3. Sniffing Port 443 (HTTPS)... (Waiting for 5 packets)')
    packets = sniff(filter="port 443", count=5) 
    print_details(packets) 

    # 4. Port 53 Sniff
    print('\n4. Sniffing Port 53 (DNS)... (Waiting for 5 packets)')
    packets = sniff(filter="src port 53", count=5)
    print_details(packets)

except PermissionError:
    print("\n[!] ERROR: You don't have permission to sniff packets.")
    print("[!] Please run as Administrator.")
except Exception as e:
    print(f"\n[!] An unexpected error occurred: {e}")