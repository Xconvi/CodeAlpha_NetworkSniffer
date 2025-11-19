# CODE-ALPHA
CODE ALPHA INTERNSHIP PROJECTS FOR CYBERSECURITY

Basic Network Sniffer

A Python-based network packet analyzer developed during the CodeAlpha Cyber Security Internship. This tool uses the scapy library to capture and analyze network traffic in real-time, demonstrating fundamental concepts of packet sniffing, protocol analysis, and data extraction.

🚀 Features

Packet Capture: Sniffs network traffic on the local interface.

Protocol Filtering: specific filters for:

ICMP (Ping)

HTTP (Port 80)

HTTPS (Port 443)

DNS (Port 53)

Detailed Analysis: Extracts and displays:

Source and Destination IP addresses

Protocols (TCP, UDP, ICMP)

Raw Payload data (decoded to UTF-8 where possible)

IPv6 Support: Handles both IPv4 and IPv6 packet structures.

🛠️ Prerequisites

Before running this script, ensure you have the following installed:

Python 3.x

Scapy Library:

pip install scapy


Npcap (Windows Only):

Required for sniffing on Windows.

Download from npcap.com.

Important: During installation, check the box "Install Npcap in WinPcap API-compatible Mode".

💻 Usage

Network sniffing requires raw socket access, so the script must be run with administrative privileges.

Windows

Open PowerShell or Command Prompt as Administrator and run:

python sniffer.py


Linux / macOS

Run with sudo:

sudo python3 sniffer.py


📝 Ethical Disclaimer

This tool is for Educational Purposes Only.
Network sniffing should only be performed on networks you own or have explicit permission to audit. Unauthorized interception of network traffic is illegal and unethical. The developer assumes no liability for misuse of this software.

👨‍💻 Author

MBA CHIBUIKE MOSES
CodeAlpha Cyber Security Intern
