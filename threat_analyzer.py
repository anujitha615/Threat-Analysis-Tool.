import nmap
import requests
import scapy.all as scapy
import yara

# ===========================
# 🔹 FUNCTION: Port Scanner
# ===========================
def scan_ports(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, '1-1024', '-sV')
    for host in scanner.all_hosts():
        print(f"\n🔍 Scanning Host: {host}")
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port]['name']
                print(f"Port {port}: {state} ({service})")

# ===========================
# 🔹 FUNCTION: Packet Sniffer
# ===========================
def packet_sniffer(interface):
    print(f"📡 Sniffing packets on {interface}...\n")
    scapy.sniff(iface=interface, store=False, prn=lambda pkt: pkt.summary())

# ===========================
# 🔹 FUNCTION: Threat Intelligence Lookup
# ===========================
def check_ip_threat(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": "YOUR_VIRUSTOTAL_API_KEY"}  # Get an API Key from VirusTotal
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print(f"🚨 Threat Report for {ip}: {data['data']['attributes']['last_analysis_stats']}")
    else:
        print("⚠️ Unable to fetch threat data. Check API Key.")

# ===========================
# 🔹 FUNCTION: Malware Detection (YARA)
# ===========================
def scan_malware(file_path, yara_rule):
    rules = yara.compile(filepath=yara_rule)
    matches = rules.match(file_path)
    
    if matches:
        print(f"🚨 Malware Detected in {file_path}!\nMatched Rules: {matches}")
    else:
        print(f"✅ {file_path} is clean.")

# ===========================
# 🔹 MENU SYSTEM
# ===========================
while True:
    print("\nThreat Analysis Tool")
    print("1. Scan a target for open ports")
    print("2. Sniff network packets on an interface")
    print("3. Check an IP address for threats")
    print("4. Scan a file for malware using YARA")
    print("5. Exit")
    
    choice = input("Enter your choice: ")
    
    if choice == "1":
        target = input("Enter target IP or hostname: ")
        scan_ports(target)
    elif choice == "2":
        interface = input("Enter network interface (e.g., eth0, wlan0): ")
        packet_sniffer(interface)
    elif choice == "3":
        ip = input("Enter IP address to check: ")
        check_ip_threat(ip)
    elif choice == "4":
        file_path = input("Enter file path: ")
        yara_rule = input("Enter YARA rule file path: ")
        scan_malware(file_path, yara_rule)
    elif choice == "5":
        print("Exiting... 👋")
        break
    else:
        print("⚠️ Invalid choice. Please select a valid option.")
