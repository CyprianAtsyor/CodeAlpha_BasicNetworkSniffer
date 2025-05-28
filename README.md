# CodeAlpha_BasicNetworkSniffer

# 🛡️ Basic Network Packet Sniffer

This project is a Python-based network packet sniffer built using [Scapy](https://scapy.net/). It captures and analyzes live packets on a specified network interface, providing details like source/destination IPs, protocol type, ports, HTTP requests, DNS queries, and more.

---

## 📌 Features

- Capture packets in real-time
- Decode protocols: IP, TCP, UDP, ICMP, HTTP, DNS
- Display payloads from HTTP requests
- Command-line interface to choose interface and packet count
- Has a clean terminal output formatting
- Graceful exit with Ctrl+C

---

## 🚀 Requirements

- Python 3.6+
- Scapy Library
- Linux/Unix system or Windows with Npcap
- Root or Sudo privileges for packet capture

---
## Installation 
1. Clone the repository
   `git clone https://github.com/yourusername/network-sniffer.git`
   `cd network-sniffer`

2. We Set up Python virtual environment
3. Install dependencies

---
Challenges faced
1. Permission Issues
Problem: Required root privileges for raw socket access
Solution:

Used `sudo` for running the script

Alternative: Set capabilities with `setcap cap_net_raw=eip /path/to/python`

2. Interface Detection
Problem: `eth0` not existing on modern Linux systems
Solution:

Added auto-interface detection

Modified script to accept common interface names (ens33, enp0s3)

Implemented interface listing helper function

3. Virtual Environment Conflicts
Problem: Ubuntu's PEP 668 blocking pip installs
Solution:

Created dedicated virtual environment

Used `python3 -m venv` instead of system Python

Added clear documentation for setup

4. HTTP Payload Analysis
Problem: Encrypted HTTPS traffic
Solution:

Focused on HTTP metadata (host, path)

Added clear note about HTTPS limitations

Considered MITM proxy for educational purposes

***Sample Output***
`[+] Packet: 192.168.1.15 -> 142.250.190.46 | Protocol: TCP`
  `  TCP - Source Port: 43422 -> Dest Port: 443`
 `   Flags: A`

`[+] Packet: 142.250.190.46 -> 192.168.1.15 | Protocol: TCP`
  `  TCP - Source Port: 443 -> Dest Port: 43422`
   ` Flags: PA`


---

See the [sniffer.py](sniffer.py) file for the full code.

---
## Image Code
![Code](./pycode.png)

---
Packet Output

![Packets](./packets.png)


```bash
python3 -m venv scapy-env
source scapy-env/bin/activate
pip install scapy
