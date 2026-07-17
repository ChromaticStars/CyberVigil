from datetime import datetime
from config import LOG_FILE
from stats import update_alert_stats


def log_alert(alert):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a") as logfile:

        logfile.write("\n==========================================\n")
        logfile.write(f"Timestamp : {timestamp}\n")
        logfile.write(f"Rule ID   : {alert['rule_id']}\n")
        logfile.write(f"Severity  : {alert['severity']}\n")
        logfile.write(f"Attack    : {alert['attack']}\n")
        logfile.write(f"Source IP : {alert['source']}\n")
        logfile.write(f"Message   : {alert['message']}\n")
        logfile.write("==========================================\n")


def process_alerts(alerts):

    if not alerts:
        return

    for alert in alerts:

        print("\n==========================================")
        print("            IDS ALERT")
        print("==========================================")
        print(f"Rule ID   : {alert['rule_id']}")
        print(f"Severity  : {alert['severity']}")
        print(f"Attack    : {alert['attack']}")
        print(f"Source IP : {alert['source']}")
        print(f"Message   : {alert['message']}")
        print("==========================================")

        update_alert_stats(alert["attack"])

        log_alert(alert)
