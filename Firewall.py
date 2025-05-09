import argparse
import os
import sys
import logging
import subprocess
import time
import threading
from dataclasses import dataclass
from collections import defaultdict
from scapy.all import sniff, IP, TCP
import ctypes


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def check_admin_privileges():
    if os.name == 'posix' and os.geteuid() != 0:
        print("ERROR: This script requires root privileges.")
        sys.exit(1)
    elif os.name != 'posix' and not is_admin():
        print("ERROR: This script requires Administrator privileges.")
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(description="Network Traffic Firewall Monitor")
    parser.add_argument("--log-dir", default="logs", help="Directory for log files")
    parser.add_argument("--threshold", type=int, default=40, help="Packets/sec threshold for blocking")
    parser.add_argument("--block-duration", type=int, default=300, help="Seconds before auto-unblock")
    parser.add_argument("--no-unblock", action="store_true", help="Disable automatic unblocking")
    return parser.parse_args()


def setup_logging(log_dir):
    # ensure log folder exists
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "network_monitor.log")
    # configure file logging
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    logger = logging.getLogger(__name__)
    # add console handler for immediate feedback
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    console.setFormatter(fmt)
    logger.addHandler(console)
    return logger


@dataclass
class Config:
    threshold: int
    block_duration: int
    no_unblock: bool


class FirewallMonitor:
    def __init__(self, config, whitelist, blacklist, logger):
        self.config = config
        self.whitelist = whitelist
        self.blacklist = blacklist
        self.logger = logger

        self.packet_count = defaultdict(int)
        self.blocked_ips = {}
        self.count_lock = threading.Lock()
        self.block_lock = threading.Lock()
        self.last_reset = time.monotonic()
        self.stop_event = threading.Event()

    @staticmethod
    def read_ip_file(filename):
        if not os.path.exists(filename):
            return set()
        with open(filename) as f:
            return {line.strip() for line in f if line.strip()}

    @staticmethod
    def is_nimda_worm(packet):
        if packet.haslayer(TCP) and packet[TCP].dport == 80:
            payload = bytes(packet[TCP].payload).decode(errors='ignore')
            return "GET /scripts/root.exe" in payload
        return False

    def block_ip(self, ip, reason):
        with self.block_lock:
            if ip in self.blocked_ips:
                return
            if os.name == 'posix':
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            else:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"
                ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                self.logger.info(f"Blocked {ip} due to {reason}")
            else:
                self.logger.error(f"Failed to block {ip}: {result.stderr.strip()}")
            self.blocked_ips[ip] = time.monotonic()

    def unblock_loop(self):
        while not self.stop_event.wait(60):
            if self.config.no_unblock:
                continue
            now = time.monotonic()
            to_unblock = []
            with self.block_lock:
                for ip, t in list(self.blocked_ips.items()):
                    if now - t >= self.config.block_duration:
                        to_unblock.append(ip)
            for ip in to_unblock:
                if os.name == 'posix':
                    cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                else:
                    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=Block_{ip}"]
                subprocess.run(cmd, capture_output=True, text=True)
                self.logger.info(f"Unblocked {ip} after {self.config.block_duration} seconds")
                with self.block_lock:
                    del self.blocked_ips[ip]

    def firewall_status_loop(self):
        while not self.stop_event.wait(60):
            if os.name == 'posix':
                cmd = ["iptables", "-L", "-v", "-n"]
            else:
                cmd = ["netsh", "advfirewall", "show", "currentprofile"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                self.logger.info("Firewall is active.")
            else:
                self.logger.error("Firewall may be disabled!")

    def packet_callback(self, packet):
        # initial debug print for first packet
        if not hasattr(self, '_first_packet_logged'):
            print("Monitoring: first packet received")
            self.logger.info("First packet captured, entering monitoring loop")
            self._first_packet_logged = True

        if not packet.haslayer(IP):
            return
        src = packet[IP].src
        if src in self.whitelist:
            return
        if src in self.blacklist:
            self.block_ip(src, "blacklist entry")
            return
        if self.is_nimda_worm(packet):
            self.block_ip(src, "Nimda worm detected")
            return

        now = time.monotonic()
        with self.count_lock:
            self.packet_count[src] += 1
        if now - self.last_reset >= 1:
            with self.count_lock:
                counts = dict(self.packet_count)
                self.packet_count.clear()
            for ip, count in counts.items():
                rate = count / (now - self.last_reset)
                if rate > self.config.threshold:
                    self.block_ip(ip, f"high traffic ({rate:.2f} pkt/sec)")
            self.last_reset = now

    def start(self):
        print("Starting network monitor...")
        self.logger.info("Starting network traffic monitoring")
        threading.Thread(target=self.unblock_loop, daemon=True).start()
        threading.Thread(target=self.firewall_status_loop, daemon=True).start()
        sniff(filter="ip", prn=self.packet_callback, store=False)

    def shutdown(self):
        self.stop_event.set()
        self.logger.info("Shutdown signal received, stopping monitor")


def main():
    args = parse_args()
    check_admin_privileges()
    logger = setup_logging(args.log_dir)
    logger.info("Logging initialized. Log file: %s", os.path.join(args.log_dir, "network_monitor.log"))
    print(f"Logging initialized. Check console and {os.path.join(args.log_dir,'network_monitor.log')}")

    config = Config(args.threshold, args.block_duration, args.no_unblock)
    whitelist = FirewallMonitor.read_ip_file("whitelist.txt")
    blacklist = FirewallMonitor.read_ip_file("blacklist.txt")

    monitor = FirewallMonitor(config, whitelist, blacklist, logger)
    try:
        monitor.start()
    except KeyboardInterrupt:
        monitor.shutdown()
        print("Network monitor stopped by user")


if __name__ == "__main__":
    main()
