from scapy.all import get_if_list, get_if_addr

print("--- Mencari Interface Jaringan yang Aktif ---")
print("Cari baris yang IP-nya sama dengan hasil 'ipconfig' Anda:\n")

for iface in get_if_list():
    try:
        ip = get_if_addr(iface)
        # Kita hanya tampilkan yang punya IP
        if ip and ip != '0.0.0.0':
            print(f"Interface: {iface}")
            print(f"IP       : {ip}")
            print("-" * 30)
    except:
        pass