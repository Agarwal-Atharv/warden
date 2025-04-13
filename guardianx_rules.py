import pyshark
from collections import defaultdict, deque
import time
import socketio
import requests
import subprocess


def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except:
        return None

server_ip = get_public_ip()
print(f"🌐 Server Public IP: {server_ip}")

sio = socketio.Client()

try:
    sio.connect('http://localhost:5000')
    print("[SOCKET] Connected to dashboard")
except Exception as e:
    print(f"[SOCKET] Connection failed: {e}")

print("🛡️  GuardianX Rule Engine started...")

# Settings
PORTSCAN_THRESHOLD = 20
PORTSCAN_WINDOW = 5  # seconds

DDOS_THRESHOLD = 100
DDOS_WINDOW = 5  # seconds

COOLDOWN_SECONDS = 10

ip_ports = defaultdict(lambda: deque())
ip_packets = defaultdict(lambda: deque())
alert_cooldown = {}
blocked_ips = set()

capture = pyshark.LiveCapture(interface='eth0')

def process_packet(pkt):
    try:
        timestamp = time.time()
        if not hasattr(pkt, 'ip') or not hasattr(pkt, 'transport_layer'):
            return

        src_ip = pkt.ip.src
        if src_ip == server_ip:
            return

        dst_port = int(pkt[pkt.transport_layer].dstport)

        # --- Port scan detection ---
        ip_ports[src_ip].append((timestamp, dst_port))
        while ip_ports[src_ip] and timestamp - ip_ports[src_ip][0][0] > PORTSCAN_WINDOW:
            ip_ports[src_ip].popleft()

        recent_ports = {p[1] for p in ip_ports[src_ip]}
        if len(recent_ports) >= PORTSCAN_THRESHOLD:
            if timestamp - alert_cooldown.get(src_ip + "_portscan", 0) > COOLDOWN_SECONDS:
                alert = f"🚨 Port scan detected from {src_ip} ({len(recent_ports)} ports in {PORTSCAN_WINDOW}s)"
                print(alert)
                sio.emit('alert', alert)
                alert_cooldown[src_ip + "_portscan"] = timestamp

                if src_ip not in blocked_ips:
                    subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", src_ip, "-j", "DROP"])
                    blocked_ips.add(src_ip)
                    block_alert = f"🚫 Blocked IP {src_ip} due to port scan"
                    print(block_alert)
                    sio.emit('alert', block_alert)

            ip_ports[src_ip].clear()

        # --- DDoS detection: flooding same port ---
        ddos_key = f"{src_ip}:{dst_port}"
        ip_packets[ddos_key].append(timestamp)
        while ip_packets[ddos_key] and timestamp - ip_packets[ddos_key][0] > DDOS_WINDOW:
            ip_packets[ddos_key].popleft()

        if len(ip_packets[ddos_key]) >= DDOS_THRESHOLD:
            ddos_alert_key = ddos_key + "_ddos"
            if timestamp - alert_cooldown.get(ddos_alert_key, 0) > COOLDOWN_SECONDS:
                alert = f"🚨 DDoS detected from {src_ip} targeting port {dst_port} ({len(ip_packets[ddos_key])} packets in {DDOS_WINDOW}s)"
                print(alert)
                sio.emit('alert', alert)
                alert_cooldown[ddos_alert_key] = timestamp

                if src_ip not in blocked_ips:
                    subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", src_ip, "-j", "DROP"])
                    blocked_ips.add(src_ip)
                    block_alert = f"🚫 Blocked IP {src_ip} due to DDoS"
                    print(block_alert)
                    sio.emit('alert', block_alert)

            ip_packets[ddos_key].clear()

    except Exception as e:
        print(f"⚠️  Packet error: {e}")

for pkt in capture.sniff_continuously():
    process_packet(pkt)
