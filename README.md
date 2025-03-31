# Threat Analysis Tool

## Overview
Threat Analysis Tool is a powerful cybersecurity tool designed to help security professionals analyze potential threats. It includes functionalities such as port scanning, packet sniffing, IP threat intelligence lookup, and malware detection using YARA rules.

## Features
- 🔍 **Port Scanning**: Scan for open ports on a target system and identify running services.
- 📡 **Packet Sniffing**: Monitor network packets on a selected network interface.
- 🚨 **IP Threat Intelligence Lookup**: Check if an IP address is associated with malicious activity using VirusTotal API.
- 🦠 **Malware Detection**: Scan files for malware using YARA rules.
- 🌍 **Custom Watermark**: Displays an encrypted globe with the author's name as a watermark.

## Installation
### Prerequisites
- Python 3.8+
- Kali Linux / Windows
- Virtual Environment (Recommended)
- VirusTotal API Key (for threat intelligence lookup)

### Setup
1. **Clone the Repository:**
   ```sh
   git clone https://github.com/yourusername/threat-analysis-tool.git
   cd threat-analysis-tool
   ```

2. **Create a Virtual Environment:**
   ```sh
   python -m venv myenv
   source myenv/bin/activate  # Linux/macOS
   myenv\Scripts\activate  # Windows
   ```

3. **Install Required Dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

4. **Set Up Environment Variables:**
   Create a `.env` file and add your VirusTotal API Key:
   ```sh
   echo "VIRUSTOTAL_API_KEY=your_api_key" > .env
   ```

## Usage
Run the tool using:
```sh
python threat_analyzer.py
```
You will be presented with a menu:
```
1. Scan Ports
2. Sniff Packets
3. Check IP Threat
4. Scan for Malware
5. Exit
```
Select an option and follow the on-screen instructions.

## Requirements
The tool requires the following Python packages:
- `nmap`
- `requests`
- `scapy`
- `yara-python`
- `python-dotenv`
- `tabulate`

Install them using:
```sh
pip install -r requirements.txt
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author
Developed by **[Your Name]**
GitHub: [Your GitHub Profile](https://github.com/yourusername)

## Disclaimer
This tool is for educational and ethical hacking purposes only. Use it responsibly and only with proper authorization.

