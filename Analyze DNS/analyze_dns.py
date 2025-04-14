# Javier Ferrándiz Fernández - 05/12/2024 - https://github.com/javisys
import pyshark
from collections import defaultdict
import datetime
import requests

# Blacklist of suspicious domains (expand as needed)
BLACKLIST = [
    "malicious.com",
    "suspicious.net",
    "phishing.org"
]

# Threshold for DNS Tunneling detection
DNS_TUNNEL_THRESHOLD = 10  # Number of queries from the same IP to the same domain

# Statistics and tracking
dns_statistics = defaultdict(int)
query_tracker = defaultdict(lambda: defaultdict(int))
suspicious_queries = []

def log_message(message, logfile="dns_log.txt"):
    """Write a message to a log file."""
    with open(logfile, "a") as log:
        log.write(f"{datetime.datetime.now()} - {message}\n")

def check_virustotal(domain, api_key):
    """Check a domain against VirusTotal API."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()
        if result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
            return True
    except requests.RequestException as e:
        log_message(f"[ERROR] VirusTotal API request failed: {e}")
    return False

def analyze_dns_traffic(interface, duration=60, use_virustotal=False, virustotal_api_key=None):
    """
    Capture and analyze DNS traffic in real-time.
    Args:
        interface (str): Network interface to monitor.
        duration (int): Duration in seconds for the capture.
        use_virustotal (bool): Whether to use VirusTotal API for domain checks.
        virustotal_api_key (str): VirusTotal API key.
    """
    print(f"Starting DNS analysis on interface {interface} for {duration} seconds...")
    try:
        capture = pyshark.LiveCapture(interface=interface, bpf_filter='udp port 53')
    except pyshark.tshark.tshark.TSharkNotFoundException as e:
        print(f"TShark not found. Please ensure it is installed and added to your PATH. Error: {e}")
        return

    start_time = datetime.datetime.now()
    
    try:
        for packet in capture.sniff_continuously():
            if (datetime.datetime.now() - start_time).seconds > duration:
                break
            
            if hasattr(packet, 'dns'):
                try:
                    dns_layer = packet.dns
                    query_name = str(dns_layer.qry_name)
                    query_type = str(dns_layer.qry_type)
                    src_ip = packet.ip.src
                    
                    dns_statistics[query_name] += 1
                    query_tracker[query_name][src_ip] += 1
                    
                    log_message(f"DNS Query: {query_name}, Type: {query_type}, From: {src_ip}")
                    
                    # Blacklist detection
                    if any(blacklisted in query_name for blacklisted in BLACKLIST):
                        log_message(f"[ALERT] Blacklisted domain detected: {query_name} from {src_ip}")
                        suspicious_queries.append((query_name, src_ip, "Blacklist"))
                    
                    # DNS Tunneling detection
                    if query_tracker[query_name][src_ip] > DNS_TUNNEL_THRESHOLD:
                        log_message(f"[ALERT] Possible DNS tunneling: {query_name} queried {query_tracker[query_name][src_ip]} times by {src_ip}")
                        suspicious_queries.append((query_name, src_ip, "DNS Tunneling"))
                    
                    # VirusTotal API check
                    if use_virustotal and virustotal_api_key:
                        if check_virustotal(query_name, api_key=virustotal_api_key):
                            log_message(f"[ALERT] Malicious domain detected via VirusTotal: {query_name}")
                            suspicious_queries.append((query_name, src_ip, "VirusTotal"))
                
                except AttributeError as e:
                    log_message(f"[ERROR] AttributeError: {e}")
                except Exception as e:
                    log_message(f"[ERROR] Unexpected error: {e}")
    
    except KeyboardInterrupt:
        print("Capture interrupted by user.")
    
    print("Analysis completed. Generating report...")
    generate_report()

def generate_report(output_file="dns_report.txt"):
    """Generate a report with DNS traffic statistics and suspicious queries."""
    with open(output_file, "w") as report:
        report.write("===== DNS TRAFFIC REPORT =====\n")
        report.write(f"Date: {datetime.datetime.now()}\n\n")
        
        # General statistics
        report.write("===== DNS Query Statistics =====\n")
        for domain, count in dns_statistics.items():
            report.write(f"{domain}: {count} queries\n")
        
        # Suspicious queries
        report.write("\n===== Suspicious Queries =====\n")
        if suspicious_queries:
            for query, src_ip, reason in suspicious_queries:
                report.write(f"{query} from {src_ip} - Reason: {reason}\n")
        else:
            report.write("No suspicious queries detected.\n")

        print(f"Report saved to {output_file}")

# Run the DNS Analyzer
if __name__ == "__main__":
    interface = input("Enter network interface (eth0, wlan0...): ")
    duration = int(input("Enter capture duration in seconds: "))
    use_virustotal = input("Use VirusTotal API? (yes/no): ").lower() == "yes"
    virustotal_api_key = None
    if use_virustotal:
        virustotal_api_key = input("Enter your VirusTotal API key: ")
    
    analyze_dns_traffic(interface, duration, use_virustotal, virustotal_api_key)

