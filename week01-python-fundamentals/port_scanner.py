"""
Network Port Scanner - Day 2, Session 1
Defense Application: Network reconnaissance and vulnerability assessment
Use Case: Scanning Nigerian government/corporate networks for unauthorized services
"""

import socket 
import sys
from datetime import datetime

# Common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

def scan_port(target_ip, port, timeout=1):
    """
    Scan a single port on the target IP
    Returns True if port is open, False otherwise
    """
    try:
        # Create a socket object (think of it as a phone line)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #Set timeout (don't wait forever)
        sock.settimeout(timeout)

        # Try to connect to the port
        result = sock.connect_ex((target_ip, port))

        # Close the connection
        sock.close()

        # Result == 0 means connection successful (port is open)
        
        return result == 0

    except socket.gaierror:
        print(f"Error: Could not resolve hostname {target_ip}")
        return False
    except socket.error:
        print(f"Error: Could not connect to {target_ip}")
    return False 
         
     
def get_service_name(port):
    """
    Get the common service name for a port
    """
    return COMMON_PORTS.get(port, "Unknown Service")

def scan_target(target_ip, ports_to_scan):
    """
    Scan multiple ports on a target
    """
    print("=" * 70)
    print(f"NETWORK PORT SCANNER - DEFENSE SECURITY TOOL")
    print("=" * 70)
    print("=Target: {target_ip}")
    print(f"scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"=" * 70)
    print()

    open_ports = []

    print("Scanning in progress...\n")

    for port in ports_to_scan:
        sys.stdout.write(f"\rScanning port {port}...")
        sys.stdout.flush()

        if scan_port(target_ip, port):
            service = get_service_name(port)
            open_ports.append((port, service))
            print(f"\r[OPEN] Port {port}: {service}")
    print("\n")
    print("=" * 70)
    print("SCAN RESULTS")
    print("=" * 70)

    if open_ports:
        print(f"\nFound {len(open_ports)} open port(s):\n")
        for port, service in open_ports:
            risk_level = assess_risk(port)
            print(f" Port {port:5} | {service:15} | Risk {risk_level}")
    else: 
        print("\nNo open ports found in the scanned range.")

    print("\n" + "=" * 70)
    print("Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S)}")
    print("=" * 70)

    return open_ports

def assess_risk(port):
    """
    Assess security risk level of an open port
    Based on common attack vectors in Nigerian cyberspace
    """
    high_risk = [21, 23, 3389, 445] # FTP, Telnet, RDP, SMB - commonly exploited
    medium_risk = [22, 25, 110, 143]  # SSH, SMTP, POP3, IMAP

    if port in high_risk:
        return "HIGH ⚠️"
    elif port in medium_risk:
        return "MEDIUM ⚡"
    else: 
        return "LOW ✓"

def save_scan_report(target_ip, open_ports, filename="scan_report.txt"):
    """
    Save scan results to a file for later analysis
    """
    with open(filename, "a", encoding="utf-8") as report:
        report.write(f"\n{'=' * 70}\n")
        report.write(f"Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"Target: {target_ip}\n")
        report.write(f"{'=' * 70}\n\n")
        
        if open_ports:
            for port, service in open_ports:
                risk = assess_risk(port)
                report.write(f"Port {port} | {service} | Risk: {risk}\n")
        else:
            report.write("No open ports detected.\n")
        
        report.write(f"\n{'=' * 70}\n")
def main():
    """
    Main program
    """
    
    print("\n🛡️  DEFENSE PORT SCANNER v1.0\n")

    # Get target from user
    target = input("Enter target IP address or hostname (e.g., scanme.nmap.org): ").strip()

    if not target:
        print("Error: No target specified!")
        return
   # Resolve hostname to IP
    try:
        target_ip = socket.gethostbyname(target)
        print(f"Resolved {target} to {target_ip}\n")
    except socket.gaierror:
        print(f"Error: Could not resolve {target}")
        return
    
    # Choose scan type
    print("Scan Options:")
    print("1. Quick Scan (Common 15 ports)")
    print("2. Standard Scan (Top 100 ports)")
    print("3. Custom Port Range")
    
    choice = input("\nSelect scan type (1-3): ").strip()
    
    if choice == "1":
        ports = list(COMMON_PORTS.keys())
    elif choice == "2":
        # Top 100 most common ports
        ports = list(range(1, 101))
    elif choice == "3":
        start = int(input("Start port: "))
        end = int(input("End port: "))
        ports = list(range(start, end + 1))
    else:
        print("Invalid choice!")
        return
    
    # Perform scan
    open_ports = scan_target(target_ip, ports)
    
    # Save report
    save_report = input("\nSave report to file? (y/n): ").strip().lower()
    if save_report == 'y':
        save_scan_report(target_ip, open_ports)
        print("✓ Report saved to scan_report.txt")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(0)

