import threading
import time
import tkinter as tk
from tkinter import ttk
import os
import sys
import logging

# Ensure the monitor module is importable from this directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Try importing based on actual monitor filename
try:
    from Firewall import FirewallMonitor, Config, setup_logging
except ImportError:
    from Firewall import FirewallMonitor, Config, setup_logging

# Initialize logging for both GUI and monitor
logger = setup_logging("logs")

# Load IP lists
whitelist = FirewallMonitor.read_ip_file("whitelist.txt")
blacklist = FirewallMonitor.read_ip_file("blacklist.txt")

# Configuration for monitoring
config = Config(threshold=40, block_duration=300, no_unblock=False)

# Instantiate the monitor with the shared logger
monitor = FirewallMonitor(config, whitelist, blacklist, logger)

class FirewallGUI(tk.Tk):
    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor
        self.title("Firewall Monitor GUI")
        self.geometry("400x300")

        # Treeview to display blocked IPs and times
        self.tree = ttk.Treeview(self, columns=("ip", "blocked_since"), show="headings")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("blocked_since", text="Blocked Since")
        self.tree.column("ip", width=120)
        self.tree.column("blocked_since", width=150)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Control buttons
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        refresh_btn = tk.Button(btn_frame, text="Refresh", command=self.update_list)
        refresh_btn.pack(side=tk.LEFT)
        quit_btn = tk.Button(btn_frame, text="Quit", command=self.quit)
        quit_btn.pack(side=tk.RIGHT)

        # Schedule first update
        self.after(1000, self.update_list)

    def update_list(self):
        # Clear current entries
        for item in self.tree.get_children():
            self.tree.delete(item)
        # Populate with current blocked IPs
        for ip, ts in self.monitor.blocked_ips.items():
            since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            self.tree.insert("", tk.END, values=(ip, since))
        # Schedule next refresh
        self.after(1000, self.update_list)

if __name__ == "__main__":
    # Start the monitor in a background daemon thread
    threading.Thread(target=monitor.start, daemon=True).start()
    # Launch the GUI main loop
    app = FirewallGUI(monitor)
    app.mainloop()
