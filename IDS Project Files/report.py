from datetime import datetime
from stats import (
    packet_stats,
    alert_stats,
    source_ip_stats,
    destination_port_stats,
    start_time
)

import time


def generate_report():

    runtime = int(time.time() - start_time)

    hours = runtime // 3600
    minutes = (runtime % 3600) // 60
    seconds = runtime % 60

    with open("ids_report.txt", "w") as report:

        report.write("=========================================\n")
        report.write("      INTRUSION DETECTION SYSTEM REPORT\n")
        report.write("=========================================\n\n")

        report.write(f"Generated : {datetime.now()}\n")
        report.write(f"Runtime   : {hours}h {minutes}m {seconds}s\n\n")

        report.write("========== Packet Statistics ==========\n")
        report.write(f"Total Packets : {packet_stats['TOTAL']}\n")
        report.write(f"TCP Packets   : {packet_stats['TCP']}\n")
        report.write(f"UDP Packets   : {packet_stats['UDP']}\n")
        report.write(f"ICMP Packets  : {packet_stats['ICMP']}\n")
        report.write(f"Other Packets : {packet_stats['OTHER']}\n\n")

        report.write("============== Alerts ===============\n")

        total_alerts = 0

        if len(alert_stats) == 0:

            report.write("No alerts detected.\n")

        else:

            for attack, count in alert_stats.items():

                report.write(f"{attack:<25}{count}\n")

                total_alerts += count

        report.write(f"\nTotal Alerts : {total_alerts}\n\n")

        report.write("========== Top Source IPs ===========\n")

        if len(source_ip_stats) == 0:

            report.write("No packets captured.\n")

        else:

            for ip, count in source_ip_stats.most_common(5):

                report.write(f"{ip:<20}{count} packets\n")

        report.write("\n======= Top Destination Ports =======\n")

        if len(destination_port_stats) == 0:

            report.write("No destination ports recorded.\n")

        else:

            for port, count in destination_port_stats.most_common(5):

                report.write(f"Port {port:<6}{count} packets\n")

        report.write("\n=========================================\n")
        report.write("           END OF REPORT\n")
        report.write("=========================================\n")
