import tkinter as tk
import threading
import time

from capture import start_capture, stop_capture
from parser import parse_packet
from detector import run_detectors
from logger import process_alerts
from report import generate_report
from gui import IDS_GUI
from stats import (
    packet_stats,
    alert_stats,
    source_ip_stats,
    source_port_stats,
    update_packet_stats
)

capture_running = False
start_time = None
# GUI

root = tk.Tk()
gui = IDS_GUI(root)

# Packet Processing

def process_packet(packet):

    data = parse_packet(packet)

    if data is None:
        return

    update_packet_stats(data)

    # GUI Packet Display

    gui.add_packet(data)

    # IDS Detection

    alerts = run_detectors(packet, data)

    if alerts:

        process_alerts(alerts)

        for alert in alerts:

            gui.add_alert(alert)
            gui.footer.config(text=f"Alert: {alert['attack']}")

    # Update GUI Statistics
    stats = {

        "TOTAL": packet_stats["TOTAL"],

        "TCP": packet_stats["TCP"],

        "UDP": packet_stats["UDP"],

        "ICMP": packet_stats["ICMP"],

        "ALERTS": sum(alert_stats.values())

    }

    gui.update_statistics(stats)

    # Threat Intelligence panel (alert types / top source IPs / top source ports)
    gui.update_alert_types(alert_stats)
    gui.update_top_sources(source_ip_stats)
    gui.update_top_ports(source_port_stats)


# Buttons

capture_thread = None

def start_ids():

    global capture_running
    global start_time

    if capture_running:
        return

    capture_running = True
    start_time = time.time()
    gui.set_status(True)
    gui.footer.config(text="Capturing packets...")
    update_runtime()
    
    threading.Thread(
        target=start_capture,
        args=(process_packet,),
        daemon=True
    ).start()
    gui.clear_packets()
    gui.clear_alerts()
    gui.clear_intel()
    gui.start_button.config(state="disabled")
    gui.stop_button.config(state="normal")
    
def stop_ids():

    global capture_running
    if not capture_running:
        return
    
    capture_running = False
    stop_capture()

    gui.set_status(False)

    gui.footer.config(text="IDS stopped")

    generate_report()

    gui.footer.config(text="Report generated successfully")
    gui.start_button.config(state="normal")
    gui.stop_button.config(state="disabled")

def update_runtime():

    if not capture_running:
        return

    elapsed = int(time.time() - start_time)

    gui.update_runtime(elapsed)

    gui.root.after(1000, update_runtime)

def create_report():

    generate_report()
    gui.show_info_dialog(
        "Report",
        "IDS report generated successfully.",
        kind="success"
    )
    gui.footer.config(text="Report generated successfully")
    
def exit_program():

    stop_capture()

    root.destroy()

gui.start_button.config(command=start_ids)
gui.stop_button.config(command=stop_ids)
gui.report_button.config(command=create_report)
gui.clear_button.config(command=gui.clear_alerts)
gui.exit_button.config(command=exit_program)

# Start GUI

root.mainloop()
