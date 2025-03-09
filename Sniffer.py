import os
import threading
import json
from datetime import datetime
from tkinter import *
from tkinter import scrolledtext, filedialog, messagebox
from scapy.all import sniff, IP, TCP, UDP, DNS, ARP, Raw, Ether


LOGS_FOLDER = "logs"
SUSPICIOUS_KEYWORDS = ['password', 'login', 'card', 'bank', 'secret']
ARP_CACHE = {}
is_sniffing = False

FILTER_SRC_IP = ""
FILTER_DST_IP = ""
FILTER_PROTOCOL = ""
FILTER_PORT = ""
FILTER_KEYWORD = ""


if not os.path.exists(LOGS_FOLDER):
    os.makedirs(LOGS_FOLDER)

log_filename = f"{LOGS_FOLDER}/packet_log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"

def log_data(log_entry):
    with open(log_filename, "a") as log_file:
        json.dump(log_entry, log_file, indent=4)
        log_file.write(",\n")

def display_output(text, alert=False):
    output_text.insert(END, text + "\n")
    output_text.see(END)
    if alert:
        messagebox.showwarning("Alert", text)


def detect_dns(packet):
    if packet.haslayer(DNS) and packet[DNS].qd:
        queried_domain = packet[DNS].qd.qname.decode()
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "DNS Request",
            "domain": queried_domain
        }
        display_output(f"[DNS Request] Domain Visited: {queried_domain}")
        log_data(log_entry)


def detect_arp_spoofing(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        if src_ip in ARP_CACHE and ARP_CACHE[src_ip] != src_mac:
            alert_msg = f"[MITM DETECTED] Possible ARP Spoofing: IP {src_ip} changed from {ARP_CACHE[src_ip]} to {src_mac}"
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "MITM Alert",
                "source_ip": src_ip,
                "spoofed_mac": src_mac
            }
            display_output(alert_msg, alert=True)
            log_data(log_entry)
        else:
            ARP_CACHE[src_ip] = src_mac


def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Filtering Logic
        if FILTER_SRC_IP and ip_src != FILTER_SRC_IP:
            return
        if FILTER_DST_IP and ip_dst != FILTER_DST_IP:
            return
        if FILTER_PROTOCOL and str(protocol) != FILTER_PROTOCOL:
            return

        log_entry = {
            "timestamp": timestamp,
            "source_ip": ip_src,
            "destination_ip": ip_dst,
            "protocol": protocol
        }

        if packet.haslayer(TCP):
            log_entry["src_port"] = packet[TCP].sport
            log_entry["dst_port"] = packet[TCP].dport
            if FILTER_PORT and (str(packet[TCP].sport) != FILTER_PORT and str(packet[TCP].dport) != FILTER_PORT):
                return

        elif packet.haslayer(UDP):
            log_entry["src_port"] = packet[UDP].sport
            log_entry["dst_port"] = packet[UDP].dport
            if FILTER_PORT and (str(packet[UDP].sport) != FILTER_PORT and str(packet[UDP].dport) != FILTER_PORT):
                return

        display_output(f"\n[{timestamp}] Packet Captured: {log_entry}")
        log_data(log_entry)

        detect_dns(packet)

        detect_arp_spoofing(packet)

        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            log_entry["payload"] = payload
            display_output(f"    Payload Data: {payload}")
            log_data(log_entry)

            if any(keyword in payload.lower() for keyword in SUSPICIOUS_KEYWORDS):
                alert_msg = f"[SUSPICIOUS DATA DETECTED] {payload}"
                display_output(alert_msg, alert=True)
                log_data({"alert": alert_msg})


def start_sniffer():
    global is_sniffing
    if not is_sniffing:
        is_sniffing = True
        display_output("[+] Packet Sniffer Started...")
        threading.Thread(target=lambda: sniff(prn=process_packet, store=False)).start()

def stop_sniffer():
    global is_sniffing
    if is_sniffing:
        is_sniffing = False
        display_output("[!] Packet Sniffer Stopped.")


def view_logs():
    file_path = filedialog.askopenfilename(initialdir=LOGS_FOLDER, title="Select Log File")
    if file_path:
        with open(file_path, "r") as log_file:
            content = log_file.read()
        display_output(f"\n=== LOG FILE CONTENT ===\n{content}")


root = Tk()
root.title("Advanced Packet Sniffer - With Filters & Logs")
root.geometry("800x650")
root.configure(bg="#1e1e1e")

btn_style = {
    "bg": "#2d2d2d",
    "fg": "white",
    "activebackground": "#3d3d3d",
    "activeforeground": "white"
}

start_button = Button(root, text="Start Sniffer", command=start_sniffer, **btn_style)
start_button.pack(pady=5)

stop_button = Button(root, text="Stop Sniffer", command=stop_sniffer, **btn_style)
stop_button.pack(pady=5)

view_logs_button = Button(root, text="View Logs", command=view_logs, **btn_style)
view_logs_button.pack(pady=5)

output_text = scrolledtext.ScrolledText(root, width=100, height=30, bg="#1e1e1e", fg="white", insertbackground='white')
output_text.pack(pady=10)

root.mainloop()
