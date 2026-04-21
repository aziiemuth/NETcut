# 🗡️ Network Recon System (Netcut)

Sebuah aplikasi berbasis Web untuk melakukan pemindaian jaringan (_Network Scanning_) dan pemutusan koneksi internet (_ARP Spoofing_) pada jaringan lokal. Didesain dengan antarmuka **Cyber Security Dashboard** yang modern dan premium.

## ✨ Fitur Utama

- **Auto-Detection Network**: Otomatis mendeteksi Gateway (Router) dan Interface aktif saat berpindah WiFi.
- **Smart Device Identification**: Mengungkap identitas perangkat menggunakan MAC Vendor Lookup, Hostname DNS, dan NetBIOS.
- **Private Device Recognition**: Mendeteksi perangkat (Android/iOS) yang menggunakan fitur MAC Randomization.
- **ARP Spoofing (PUTUS)**: Memutus koneksi internet target dalam satu klik.
- **Premium UI**: Menggunakan Glassmorphism, FontAwesome 6, dan SweetAlert2 untuk interaksi yang mulus.

## 📋 Persyaratan Sistem

Aplikasi ini berjalan di **Windows** dan memerlukan beberapa komponen berikut:

1.  **Python 3.x**
2.  **Npcap**: Wajib diinstal agar Scapy bisa melakukan injeksi paket.
    - [Download Npcap](https://npcap.com/#download)
    - **PENTING**: Saat instalasi, pastikan mencentang opsi **"Install Npcap in WinPcap API-compatible mode"**.
3.  **Hak Akses Admin**: Harus dijalankan melalui Terminal/CMD dengan _Run as Administrator_.

## 🚀 Cara Instalasi

1.  **Clone atau Download** repository ini.
2.  Buka Terminal (CMD/PowerShell) di folder project ini.
3.  Install dependensi Python:
    ```bash
    pip install -r requirements.txt
    ```

## 🛠️ Cara Menjalankan

1.  Buka Terminal sebagai **Administrator**.
2.  Jalankan aplikasi:
    ```bash
    python app.py
    ```
3.  Buka browser dan akses:
    `http://127.0.0.1:5000`
4.  Klik tombol **"SCAN JARINGAN"** untuk memulai.

## ⚠️ Disclaimer

Aplikasi ini dibuat untuk tujuan edukasi dan pengujian keamanan jaringan legal. Penggunaan aplikasi ini pada jaringan orang lain tanpa izin adalah tindakan ilegal. Pembuat tidak bertanggung jawab atas penyalahgunaan aplikasi ini.

---

**Build with ❤️ for Cybersecurity Enthusiasts.**
