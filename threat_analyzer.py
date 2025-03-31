"""
Threat Analysis Tool
Author: [Your Name]
GitHub: [Your GitHub URL]
License: MIT
Description: This tool provides functionalities for port scanning, packet sniffing, threat intelligence lookup, and malware detection using YARA.

        _.-'''''-._
      .'  _     _  '.
     /   (_)   (_)   \
    |  ,           ,  |
    |  \`.       .`/  |
     \  '.`'""'"`.'  /
      '.  `'---'`  .'
        '-._____.-'  
       🌍  Earth  🌎  

"""

import nmap
import requests
import scapy.all as scapy
import yara
import os
import logging
import ctypes
from dotenv import load_dotenv
from tabulate import tabulate

def display_watermark():
    print("\n======================================")
    print("        _.-'''''-._")
    print("      /'  _     _  '.")
    print("     /   (_)   (_)   \\")
    print("    |  ,           ,  |")
    print("    |  \`.       .`/  |")
    print("     \\  '.`'\"\"'`.' /")
    print("      '.  `'---'`  .'")
    print("        '-._____.-'  ")
    print("       🌍  Threat Analysis Tool  🌎")
    print(" Created by: ANUJITH A ")
    print(" GitHub: https://github.com/anujitha615/Threat-Analysis-Tool ")
    print(" License: MIT ")
    print("======================================\n")

display_watermark()

# Load environment variables
load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Ensure YARA is properly imported
try:
    import yara
    print(f"✅ YARA successfully loaded, version: {yara.__version__}")
except ImportError as e:
    raise ImportError("⚠️ YARA module not found. Ensure it is installed correctly.") from e

# Configure logging
logging.basicConfig(filename="log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# ===========================
# 🔹 FUNCTION: Port Scanner
# ===========================
def scan_ports(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, '1-1024', '-sV')
    print(f"\n🔍 Scanning Host: {target}")
    results = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port]['name']
                results.append([port, state, service])
    
    if results:
        print(tabulate(results, headers=["Port", "State", "Service"], tablefmt="grid"))
        logging.info(f"Port scan results for {target}: {results}")
    else:
        print("⚠️ No open ports found.")

# ===========================
# 🔹 FUNCTION: Packet Sniffer
# ===========================
def packet_sniffer(interface):
    print("Available Interfaces:")
    print(scapy.get_if_list())
    print(f"📱 Sniffing packets on {interface}...\n")
    try:
        scapy.sniff(iface=interface, store=False, prn=lambda pkt: print(pkt.summary()))
    except Exception as e:
        print(f"⚠️ Error: {e}")

# ===========================
# 🔹 FUNCTION: Threat Intelligence Lookup
# ===========================
def check_ip_threat(ip):
    if not API_KEY:
        print("⚠️ API Key not found. Please set VIRUSTOTAL_API_KEY in .env file.")
        return
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        print(f"🚨 Threat Report for {ip}: {stats}")
        logging.info(f"Threat report for {ip}: {stats}")
    else:
        print("⚠️ Unable to fetch threat data. Check API Key.")

# ===========================
# 🔹 FUNCTION: Malware Detection (YARA)
# ===========================
def scan_malware(file_path, yara_rule):
    if not os.path.exists(yara_rule):
        print(f"⚠️ Error: YARA rule file '{yara_rule}' not found.")
        return
    
    try:
        rules = yara.compile(filepath=yara_rule)
        matches = rules.match(file_path)
        
        if matches:
            print(f"🚨 Malware Detected in {file_path}!\nMatched Rules: {matches}")
            logging.info(f"Malware detected in {file_path}: {matches}")
        else:
            print(f"✅ {file_path} is clean.")
    except yara.SyntaxError as e:
        print(f"⚠️ YARA Syntax Error: {e}")
    except yara.Error as e:
        print(f"⚠️ YARA Error: {e}")

# ===========================
# 🔹 INTERACTIVE MENU
# ===========================
if __name__ == "__main__":
    while True:
        print("\n🔹 Threat Analysis Tool - Menu")
        print("1. Scan Ports")
        print("2. Sniff Packets")
        print("3. Check IP Threat")
        print("4. Scan for Malware")
        print("5. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            target = input("Enter target IP or domain: ")
            scan_ports(target)
        elif choice == "2":
            print("Finding available interfaces...")
            interfaces = scapy.get_if_list()
            print("Available interfaces:", interfaces)
            interface = input("Enter network interface from the list: ")
            if interface in interfaces:
                packet_sniffer(interface)
            else:
                print("⚠️ Invalid interface. Please select a valid one.")
        elif choice == "3":
            ip = input("Enter IP address to check: ")
            check_ip_threat(ip)
        elif choice == "4":
            file_path = input("Enter file path to scan: ")
            yara_rule = "D:\\pythonfiles\\Project\\yara_rules\\malware_rules.yar"
            scan_malware(file_path, yara_rule)
        elif choice == "5":
            print("Exiting... Goodbye! 👋")
            break
        else:
            print("⚠️ Invalid choice. Please select a valid option.")
