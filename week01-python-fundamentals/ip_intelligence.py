"""
IP Intelligence Gathering Tool - Day 2, Session 2
Defense Application: Threat intelligence and geolocation tracking
Use Case: Identifying origins of cyber attacks on Nigerian infrastructure
"""

import socket
import requests
import json
from datetime import datetime

def get_ip_info(ip_address):

    """
    Get detailed information about an IP address
    Uses free IP geolocation API
    """
    try:
       # Using ip-api.com (free, no key required, 45 requests/minute)
       url = f"http://ip-api.com/json/{ip_address}"

       response = requests.get(url, timeout=5)
       data = response.json()

       if data['status'] == 'success':
          return {
                'ip': data.get('query'),
                'country': data.get('country'),
                'country_code': data.get('countryCode'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'zip': data.get('zip'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'timezone': data.get('timezone'),
                'isp': data.get('isp'),
                'org': data.get('org'),
                'as': data.get('as')
          }
       else: 
          return None 
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching IP info: {e}")
        return None
    

def check_threat_level(country_code, isp):
    """
    Assess threat level based on origin
    Customize this for Nigerian security context
    """
    # High-risk countries for cyber attacks on African infrastructure
    high_risk_countries = ['CN', 'RU', 'KP', 'IR']

    # Known malicious ISP keywords
    suspicious_isps = ['tor', 'vpn', 'proxy', 'hosting', 'cloud']

    threat_level = "LOW"
    reasons = []

    if country_code in high_risk_countries:
        threat_level = "HIGH"
        reasons.append(f"Origin from high-risk country ({country_code})")

    isp_lower =isp.lower()
    for suspicious in suspicious_isps:
        if suspicious in isp_lower:
            if threat_level == "LOW":
                threat_level = "MEDIUM"
            reasons.append(f"Suspicious ISP ({suspicious} detected)")
            break 

    return threat_level, reasons


def analyze_ip(ip_address):
    """
    Complete IP analysis with threat assessment
    """
    print("=" * 70)
    print("IP INTELLIGENCE GETHERING TOOL")
    print("=" * 70)
    print(f"\nAnalyzing IP: {ip_address}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    #Get IP information
    info = get_ip_info(ip_address)

    if not info:
        print("❌ Could not retrieve IP information")
        return

    #Display geographic information
    print("📍 GEOGRAPHIC INFORMATION")
    print("_" * 70)
    print(f"  IP Address:   {info['ip']}")
    print(f"  Country:      {info['country']} ({info['country_code']})")
    print(f"  Region:       {info['region']}") 
    print(f"  City:         {info['city']}")
    print(f"  Coordinates:  {info['latitude']}, {info['longitude']}")
    print(f"  Timezone:     {info['timezone']}")

    # Display network information
    print("\n🌐 NETWORK INFORMATION")
    print("_" * 70)
    print(f" ISP:           {info['isp']}")
    print(f" Organization:  {info['org']}")
    print(f" As Number:     {info['as']}")

    # Threat assessment
    threat_level, reasons = check_threat_level(info['country_code'], info ['isp'])

    print("\n🛡️   THREAT ASSESSMENT")
    print("_" * 70)
    print(f"  Threat Level:  {threat_level}")

    if reasons:
        print(f"Reasons:")
        for reason in reasons:
            print(f"    • {reason}")
    else:
        print(f"   Status: No immediate threats detected")

    # Additional checks
    print("\n🔍 ADDITIONAL CHECKS")
    print("_" * 70)

    # Check if IP is from Nigeria
    if info['country_code'] == 'NG':
        print(f"   Domestic IP (Nigeria)")
    else:
        print(f"   ⚠ Foreign IP - Review required")

    # Check if residential or datacenter
    if any(word in info['isp'].lower() for word in ['airtel', 'mtn', 'glo', '9mobile', 'ntel']):
        print(f"  ✓ Nigerian Telecom Provider")
    elif any(word  in info['isp'].lower() for word in ['datacenter', 'hosting','cloud', 'server']):  
        print(f"    ⚠ Datacenter/Hosting IP - Possible bot or automated tool" )    

    print("\n" + "=" * 70)

    return info, threat_level


def batch_analyze(ip_list_file):
    """
    Analyze multiple IPs from a file
    Useful for analyzing firewall logs
    """
    print("\n📊 BATCH IP ANALYSIS\n")
    
    try:
        with open(ip_list_file, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        
        print(f"Analyzing {len(ips)} IP addresses...\n")

        results = []
        for ip in ips:
            info, threat = analyze_ip(ip)
            results.append({'ip': ip, 'info': info, 'threat': threat})
        print() # Spacing between results

        # Summary
        print("=" * 70)
        print("BATCH ANALYSIS SUMMARY")
        print("=" * 70)

        high_threat = sum(1 for r in results if r['threat']== 'HIGH')
        medium_threat = sum(1 for r in results if r['threat'] == 'MEDIUM')
        low_threat = sum(1 for r in results if r ['threat'] == 'LOW')

        print(f"\Total IP Analyzed: {len(results)}")
        print(f"  High Threat:   {high_threat}")
        print(f"  Medium Threat: {medium_threat}")
        print(f"  Low Threat:    {low_threat}") 

        # Save report
        with open('ip_analysis_report.json', 'w') as report:
            json.dump(results, report, indent=2)
        print(f"\n✓ Detailed report saved to ip_analysis_report.json")

    except  FileNotFoundError:
        print(f"Error: File '{ip_list_file} not found")


def main():
    """
    Main program
    """
    print("\n🛡️  IP INTELLIGENCE TOOL v1.0")
    print("Defense Security & Threat Analysis\n")
    
    print("Options:")
    print("1. Analyze single IP")
    print("2. Batch analyze from file")
    print("3. Analyze your own IP")

    choice = input("\nSelect options (1-3): ").strip()

    if choice == '1':
        ip = input("Enter IP address: ").strip()
        analyze_ip(ip)

    elif choice == '2':
        filename =  input("Enter filename (e.g., suspicious_ips.txt): ").strip()
        batch_analyze(filename)

    elif choice == '3':
        #Get user's public IP
        try:
            response = requests.get('http://api.ipify.org', timeout=5)# NOTE: ip-api free tier uses HTTP only (no HTTPS support)
            my_ip = response.text 
            print(f"\nYour public IP: {my_ip}\n")
            analyze_ip(my_ip)
        except requests.exceptions.RequestException as e:
            print(f"Error: Could not retrieve your IP ({e})")


    else:
            print("Invalid choice!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")