# Packet Sniffer Project

This is an advanced packet sniffer built with Python, featuring:

- GUI Interface with Tkinter
- JSON Log File Storage
- Advanced Filtering by IP, Port, and Protocol
- ARP Spoofing and DNS Detection
- Log Viewing from Within the GUI
- Intended for ethical and educational use only

## Requirements
To install the necessary dependencies, run:

```
pip install scapy
```

## How to Run

Clone the Repository:
```
git clone https://github.com/Zyssalone/Packet-Sniffer.git
```

Navigate to the Project Directory:
```
cd Packet-Sniffer
```

Run the Script with Administrative Privileges:
- For Windows:
```
python sniffer_with_logs.py
```
- For Linux:
```
sudo python3 sniffer_with_logs.py
```

## Folder Structure
```
/Packet-Sniffer
├── /logs               # Saved log files
├── sniffer_with_logs.py # Main sniffer script
├── README.md            # Project documentation
├── .gitignore           # Ignored files
└── LICENSE              # License details
```

## Features

- **Real-Time Packet Capture** — Capture and view packets directly in the GUI terminal.
- **Filtering Options** — Filter packets by Source IP, Destination IP, Protocol, Port, and Payload Keywords.
- **DNS Request Analysis** — Identify visited domains in real-time.
- **ARP Spoofing Detection** — Alerts for potential MITM (Man-in-the-Middle) attacks.
- **JSON Log File Storage** — Logs are saved in structured JSON format for easy analysis.
- **Log Viewer in GUI** — Easily browse and review saved logs.

## Packet Filtering
In the GUI, you can filter packets using the following criteria:

| Filter Option      | Description                                   | Example        |
|--------------------|-----------------------------------------------|-----------------|
| Source IP           | Filter packets by the sender’s IP address      | 192.168.1.5     |
| Destination IP      | Filter packets by the receiver’s IP address    | 172.217.3.110   |
| Protocol            | Filter by protocol type (e.g., TCP, UDP)      | TCP             |
| Port                | Filter packets sent/received on a specific port| 80              |
| Keyword in Payload  | Filter packets containing specific keywords   | password        |

## Security Considerations
This tool is intended strictly for educational purposes and authorized network testing. Unauthorized network monitoring may violate privacy laws. Always obtain proper consent before analyzing third-party networks.

## Contribution Guide
Contributions are welcome. To contribute:

1. Fork the repository.
2. Create a new branch for your feature or fix.
3. Commit your changes with a clear commit message.
4. Open a pull request for review.

