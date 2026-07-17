from collections import defaultdict, Counter
import time

# Packet Statistics
packet_stats = {
    "TOTAL": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "OTHER": 0
}

# Alert Statistics
alert_stats = defaultdict(int)
source_ip_stats = Counter()
source_port_stats = Counter()
destination_port_stats = Counter()
start_time = time.time()

# Packet Counters
def update_packet_stats(data):

    packet_stats["TOTAL"] += 1

    protocol = data["protocol"]

    if protocol in packet_stats:
        packet_stats[protocol] += 1
    else:
        packet_stats["OTHER"] += 1

    source_ip_stats[data["src_ip"]] += 1
    if "src_port" in data:
    	source_port_stats[data["src_port"]] += 1
    if "dst_port" in data:
    	destination_port_stats[data["dst_port"]] += 1

# Alert Counters

def update_alert_stats(attack):

    alert_stats[attack] += 1
