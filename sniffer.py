from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        if proto == 6: 
            protocol_name = "TCP"
        elif proto == 17: 
            protocol_name = "UDP"
        else: 
            protocol_name = str(proto)

        print(f"\n[+] New Packet: {src_ip} -> {dst_ip} | Protocol: {protocol_name}")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet.payload)
            if payload:
                print(f"   - Raw Data: {payload[:50].hex()}...")

print("--- Network Sniffer Starting ---")
print("Listening for traffic... (Press Ctrl+C to stop)")

sniff(prn=packet_callback, store=0)
