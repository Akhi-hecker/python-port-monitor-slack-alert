import socket
import time
import requests
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Get Slack webhook from environment
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# Targets to monitor
targets = [ 
    ("letsdefend.io", 80, "TCP"), 
    ("letsdefend.io", 443, "TCP"), 
    ("8.8.8.8", 80, "TCP")
]

# Logging function
def log_message(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open("monitor_log.txt", "a") as log_file:
        log_file.write(f"{timestamp} {message}\n")
    print(f"{timestamp} {message}")

# Port check function
def check_port(target, port, protocol): 
    try: 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        if protocol == "TCP": 
            result = s.connect_ex((target, port)) 
            s.close() 
            return result == 0
    except:
        return False

# Slack alert function
def send_slack_notification(target, port, protocol): 
    message = f"{target}:{port}/{protocol} port not responding!"
    payload = {"text": message}
    requests.post(SLACK_WEBHOOK_URL, json=payload)
    log_message(f"[ALERT] {message}")

# Main loop (every 60 mins)
while True:
    for target, port, protocol in targets:
        status = check_port(target, port, protocol)
        if not status:
            send_slack_notification(target, port, protocol)
        else:
            log_message(f"{target}:{port}/{protocol} is UP")
    log_message("All checks complete. Sleeping for 60 minutes...\n")
    time.sleep(3600)
