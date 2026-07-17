from collections import defaultdict
import time

from scapy.all import TCP

from config import (
    HIGH_TRAFFIC_THRESHOLD,
    HIGH_TRAFFIC_WINDOW,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW,
    SUSPICIOUS_PORTS
)
# IDS DATA STORAGE

packet_times = defaultdict(list)

port_activity = defaultdict(list)

syn_packets = defaultdict(list)

icmp_packets = defaultdict(list)

# ALERT CREATOR

def create_alert(rule_id, severity, attack, source, message):

    return {
        "rule_id": rule_id,
        "severity": severity,
        "attack": attack,
        "source": source,
        "message": message
    }


# RULE 1001
# HIGH TRAFFIC

def detect_high_traffic(data):

    src_ip = data["src_ip"]

    current_time = time.time()

    packet_times[src_ip].append(current_time)

    packet_times[src_ip] = [

        t

        for t in packet_times[src_ip]

        if current_time - t <= HIGH_TRAFFIC_WINDOW

    ]

    if len(packet_times[src_ip]) >= HIGH_TRAFFIC_THRESHOLD:

        return create_alert(

            1001,

            "HIGH",

            "High Traffic",

            src_ip,

            f"{len(packet_times[src_ip])} packets detected in "
            f"{HIGH_TRAFFIC_WINDOW} seconds"

        )

    return None


# RULE 1002
# PORT SCAN

def detect_port_scan(data):

    if "dst_port" not in data:

        return None

    src_ip = data["src_ip"]

    dst_port = data["dst_port"]

    current_time = time.time()

    port_activity[src_ip].append(

        (dst_port, current_time)

    )

    port_activity[src_ip] = [

        (port, timestamp)

        for port, timestamp in port_activity[src_ip]

        if current_time - timestamp <= PORT_SCAN_WINDOW

    ]

    unique_ports = {

        port

        for port, timestamp in port_activity[src_ip]

    }

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:

        return create_alert(

            1002,

            "HIGH",

            "Port Scan",

            src_ip,

            f"{len(unique_ports)} unique ports accessed "
            f"in {PORT_SCAN_WINDOW} seconds"

        )

    return None


# RULE 1003
# SYN FLOOD

SYN_THRESHOLD = 50
SYN_WINDOW = 5


def detect_syn_flood(packet, data):

    if TCP not in packet:

        return None

    flags = packet[TCP].flags

    # SYN only (no ACK)
    if flags == "S":

        src_ip = data["src_ip"]

        current_time = time.time()

        syn_packets[src_ip].append(current_time)

        syn_packets[src_ip] = [

            t

            for t in syn_packets[src_ip]

            if current_time - t <= SYN_WINDOW

        ]

        if len(syn_packets[src_ip]) >= SYN_THRESHOLD:

            return create_alert(

                1003,

                "CRITICAL",

                "SYN Flood",

                src_ip,

                f"{len(syn_packets[src_ip])} SYN packets "
                f"in {SYN_WINDOW} seconds"

            )

    return None


# RULE 1004
# ICMP FLOOD

ICMP_THRESHOLD = 50
ICMP_WINDOW = 5


def detect_icmp_flood(data):

    if data["protocol"] != "ICMP":

        return None

    src_ip = data["src_ip"]

    current_time = time.time()

    icmp_packets[src_ip].append(current_time)

    icmp_packets[src_ip] = [

        t

        for t in icmp_packets[src_ip]

        if current_time - t <= ICMP_WINDOW

    ]

    if len(icmp_packets[src_ip]) >= ICMP_THRESHOLD:

        return create_alert(

            1004,

            "HIGH",

            "ICMP Flood",

            src_ip,

            f"{len(icmp_packets[src_ip])} ICMP packets "
            f"in {ICMP_WINDOW} seconds"

        )

    return None

# RULE 1005
# SUSPICIOUS PORT ACCESS

def detect_suspicious_port(data):

    if "dst_port" not in data:
        return None

    dst_port = data["dst_port"]

    if dst_port in SUSPICIOUS_PORTS:

        return create_alert(

            1005,

            "MEDIUM",

            "Suspicious Port Access",

            data["src_ip"],

            f"Connection detected to suspicious port {dst_port}"

        )

    return None

# RUN ALL RULES

def run_detectors(packet, data):

    alerts = []
    
    detectors = [
    	
    	detect_high_traffic(data),
    	
    	detect_port_scan(data),
    	
    	detect_syn_flood(packet, data),
    	
    	detect_icmp_flood(data),
    	
    	detect_suspicious_port(data)
    	
    	]

    for alert in detectors:

        if alert is not None:

            alerts.append(alert)

    return alerts
