# IDS Configuration

# High Traffic Detection
HIGH_TRAFFIC_THRESHOLD = 50
HIGH_TRAFFIC_WINDOW = 10      # seconds

# Port Scan Detection
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = 10         # seconds

# Logging
LOG_FILE = "alerts.log"

# Suspicious Ports
SUSPICIOUS_PORTS = [
    21,
    22,
    23,
    135,
    139,
    445,
    3389
]


# Packet Capture
INTERFACE = None      # None = default interface
STORE_PACKETS = False

# Display
SHOW_PACKET_INFO = True
SHOW_FLOW_INFO = True
