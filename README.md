# Python Firewall

This is a Python-based firewall that monitors network traffic, detects high-traffic sources, and blocks malicious activity. It supports both Windows (`netsh`) and Linux (`iptables`).

## Features
✅ **Monitors network traffic** using Scapy  
✅ **Blocks IPs exceeding packet threshold**  
✅ **Blocks known malicious IPs (blacklist.txt)**  
✅ **Supports Windows Firewall (`netsh`) & Linux (`iptables`)**  
✅ **Automatically unblocks IPs after a set duration**  
✅ **Customizable logging, thresholds, and blocking rules**  
✅ **Command-line options for better control**  

---

## Installation
### **1. Install Python & Dependencies**
Make sure you have Python installed, then install required dependencies:
```bash
pip install scapy
```

---

## Usage
### **Run as Administrator (Required)**
- **Windows:** Run PowerShell as **Administrator** and execute:
  ```powershell
  python Firewall.py
  ```
- **Linux:** Run as **root**:
  ```bash
  sudo python3 Firewall.py
  ```

### **Command-Line Options**
You can customize settings using command-line arguments:
```bash
python Firewall.py --threshold 50 --block-duration 600 --log-dir /var/log/firewall
```
| Argument        | Description                                      | Default |
|---------------|--------------------------------------------------|---------|
| `--threshold` | Packets per second before blocking an IP         | `40`    |
| `--block-duration` | Time (seconds) before unblocking an IP        | `300`   |
| `--no-unblock` | Disable automatic unblocking                    | `False` |
| `--log-dir`   | Directory to store logs                         | `logs/` |

---

## Configuration
### **Whitelist & Blacklist**
- **`blacklist.txt`** → Add IPs you want to block permanently.
- **`whitelist.txt`** → Add trusted IPs that should never be blocked.

Example format:
```
192.168.1.100
10.0.0.5
203.0.113.45
```

---

## Logging
All blocked IPs and firewall status updates are logged in the specified log directory:
```bash
tail -f logs/network_monitor.log
```

---

## Unblocking IPs
- IPs automatically unblock after `BLOCK_DURATION` (default: **5 minutes**).
- To manually unblock an IP:
  - **Windows:**
    ```powershell
    netsh advfirewall firewall delete rule name=Block_192.168.1.100
    ```
  - **Linux:**
    ```bash
    sudo iptables -D INPUT -s 192.168.1.100 -j DROP
    ```

---

## Firewall Reset (If Needed)
To remove all added firewall rules:
- **Windows:**
  ```powershell
  netsh advfirewall reset
  ```
- **Linux:**
  ```bash
  sudo iptables -F
  ```

---

## License
This project is licensed under the MIT License.

