from collections import defaultdict
from scapy.all import sniff, IP, TCP
import os
import time
import sys
import subprocess
import threading
import ctypes
import argparse

# Command-line arguments for customization
parser = argparse.ArgumentParser(description="Python Firewall")
parser.add_argument("--log-dir", default="logs", help="Set log directory (default: logs)")
parser.add_argument("--threshold", type=int, default=40, help="Packets per second limit before blocking")
parser.add_argument("--block-duration", type=int, default=300, help="Seconds before an IP is unblocked")
parser.add_argument("--no-unblock", action="store_true", help="Disable automatic unblocking")
args = parser.parse_args()

THRESHOLD = args.threshold  # Max allowed packets per second
BLOCK_DURATION = args.block_duration  # Time in seconds before an IP is unblocked
LOG_DIR = args.log_dir
LOG_FILE = os.path.join(LOG_DIR, "network_monitor.log")

# Ensure log directory exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def check_admin_privileges():
    if os.name != "posix" and not is_admin():
        print("ERROR: This script requires Administrator privileges.")
        sys.exit(1)
    elif os.name == "posix" and os.geteuid() != 0:
        print("ERROR: This script requires root privileges.")
        sys.exit(1)

check_admin_privileges()

print(f"THRESHOLD: {THRESHOLD}, BLOCK_DURATION: {BLOCK_DURATION} seconds")

# Read IPs from a file
def read_ip_file(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, "r") as file:
        return {line.strip() for line in file}

# Check for Nimda worm signature
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = bytes(packet[TCP].payload).decode(errors='ignore')
        return "GET /scripts/root.exe" in payload
    return False

# Log events to a file efficiently
def log_event(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(LOG_FILE, "a") as file:
        file.write(f"[{timestamp}] {message}\n")

# Check firewall status without exposing details
def check_firewall_status():
    while True:
        time.sleep(60)
        status_command = "sudo iptables -L -v -n" if os.name == "posix" else "netsh advfirewall show currentprofile"
        result = subprocess.run(status_command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            log_event("Firewall is active.")
        else:
            log_event("ERROR: Firewall may be disabled!")

def block_ip(ip, reason):
    if ip in blocked_ips:
        return  # Prevent redundant rules
    
    if os.name == "posix":
        command = f"iptables -A INPUT -s {ip} -j DROP"
    else:
        command = f"netsh advfirewall firewall add rule name=Block_{ip} dir=in action=block remoteip={ip}"
    
    result = os.system(command)
    if result == 0:
        log_event(f"Blocking {ip} due to {reason}")
        blocked_ips[ip] = time.time()
    else:
        log_event(f"ERROR: Failed to block {ip} with command: {command}")
        print(f"ERROR: Failed to block {ip}. Check firewall settings.")

def unblock_ips():
    if args.no_unblock:
        return  # Do nothing if unblocking is disabled
    
    while True:
        time.sleep(60)
        current_time = time.time()
        to_unblock = [ip for ip, block_time in blocked_ips.items() if (current_time - block_time) >= BLOCK_DURATION]

        for ip in to_unblock:
            if os.name == "posix":
                os.system(f"iptables -D INPUT -s {ip} -j DROP")
            else:
                os.system(f"netsh advfirewall firewall delete rule name=Block_{ip}")
            
            log_event(f"Unblocked {ip} after {BLOCK_DURATION} seconds")
            del blocked_ips[ip]

def packet_callback(packet):
    if not packet.haslayer(IP):
        return  # Ignore non-IP packets

    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        return

    if src_ip in blacklist_ips:
        block_ip(src_ip, "blacklist entry")
        return
    
    if is_nimda_worm(packet):
        block_ip(src_ip, "Nimda worm detected")
        return

    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        to_remove = set()
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD:
                block_ip(ip, f"high traffic ({packet_rate:.2f} pkt/sec)")
                to_remove.add(ip)
        
        for ip in to_remove:
            packet_count.pop(ip, None)

        start_time[0] = current_time

if __name__ == "__main__":
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = {}

    print("Monitoring network traffic...")
    log_event("Started monitoring network traffic")

    unblock_thread = threading.Thread(target=unblock_ips, daemon=True)
    unblock_thread.start()

    firewall_status_thread = threading.Thread(target=check_firewall_status, daemon=True)
    firewall_status_thread.start()

    try:
        sniff(filter="ip", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nStopping network monitor...")
        log_event("Network monitor stopped by user")
    except Exception as e:
        log_event(f"Error occurred: {str(e)}")
