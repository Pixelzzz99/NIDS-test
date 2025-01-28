from scapy.all import sniff, IP, TCP, UDP, ICMP

traffic_stats = {
    "total_packets": 0,
    "protocols": {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "Other": 0
    },
    "sources": {},
    "destinations": {},
    "port_scans": {},
}

DOS_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 20


def packet_callback(packet):
    traffic_stats["total_packets"] += 1
    if packet.haslayer(TCP):
        traffic_stats["protocols"]["TCP"] += 1
        track_port_scan(packet)
    elif packet.haslayer(UDP):
        traffic_stats["protocols"]["UDP"] += 1
    elif packet.haslayer(ICMP):
        traffic_stats["protocols"]["ICMP"] += 1
    else:
        traffic_stats["protocols"]["Other"] += 1

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip in traffic_stats['sources']:
            traffic_stats['sources'][src_ip] += 1
        else:
            traffic_stats['sources'][src_ip] = 1

        if dst_ip in traffic_stats['destinations']:
            traffic_stats['destinations'][dst_ip] += 1
        else:
            traffic_stats['destinations'][dst_ip] = 1

        detect_dos(src_ip)

    print('Renewed stats:')
    print(f'Total packets: {traffic_stats["total_packets"]}')
    print(f'Protocols: {traffic_stats["protocols"]}')
    print(f'Sources: {dict(sorted(traffic_stats["sources"].items(), key=lambda item: item[1], reverse=True)[:5])}')
    print(f'Destinations: {dict(sorted(traffic_stats["destinations"].items(), key=lambda item: item[1], reverse=True)[:5])}')


def detect_dos(src_ip):
    if traffic_stats['sources'][src_ip] > DOS_THRESHOLD:
        alert = f'[ALERT] DOS attack detected from {src_ip}, packets: {traffic_stats["sources"][src_ip]}'
        print(alert)

def track_port_scan(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if src_ip not in traffic_stats['port_scans']:
            traffic_stats['port_scans'][src_ip] = set()
        traffic_stats['port_scans'][src_ip].add(dst_port)

        if len(traffic_stats['port_scans'][src_ip]) > PORT_SCAN_THRESHOLD:
            alert = f'[ALERT] Port scan detected from {src_ip}, unique ports: {len(traffic_stats["port_scans"][src_ip])}'
            print(alert)

print("Starting sniffing...")
sniff(prn=packet_callback, count=100)
