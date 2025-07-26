import re
import time
import requests
from rich import print
import ipaddress

def print_centered_header(title: str):
    width = 80
    print("=" * width)
    print(title.center(width))
    print("=" * width + "\n")

def extract_ips_from_headers(msg_obj):
    ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    headers = str(msg_obj)
    ips = list(set(re.findall(ip_regex, headers)))

    # Filter out IP-like strings with leading zeros (except single '0')
    def valid_ip(ip):
        parts = ip.split('.')
        for p in parts:
            if len(p) > 1 and p.startswith('0'):
                return False
        return True

    ips = [ip for ip in ips if valid_ip(ip)]
    return ips

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def get_geoip_country(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/country_name/", timeout=5)
        if response.status_code == 200:
            country = response.text.strip()
            if country:
                return country
    except Exception:
        pass
    return "Undefined"

def check_ip_virustotal(ip, api_key, cache):
    if ip in cache:
        return cache[ip]

    if is_private_ip(ip):
        cache[ip] = ("unchecked", "IP is private")
        return cache[ip]

    if not api_key:
        cache[ip] = ("unchecked", "IP will need to be investigated manually")
        return cache[ip]

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 429:
            while True:
                choice = input(
                    "[yellow]VirusTotal API rate limit reached.[/yellow]\n"
                    "Type 'wait' to wait 60 seconds, or 'skip' to proceed without checking: "
                ).strip().lower()
                if choice == "wait":
                    print("Waiting 60 seconds...")
                    time.sleep(60)
                    response = requests.get(url, headers=headers)
                    if response.status_code != 429:
                        break
                elif choice == "skip":
                    cache[ip] = ("unchecked", "IP will need to be investigated manually")
                    return cache[ip]
                else:
                    print("Invalid input. Please type 'wait' or 'skip'.")

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            if malicious > 0:
                comment = (f"{malicious} vendor flagged this IP as malicious"
                           if malicious == 1 else
                           f"{malicious} vendors flagged this IP as malicious")
                cache[ip] = ("malicious", comment)
            elif suspicious > 0:
                comment = (f"{suspicious} vendor flagged this IP as suspicious"
                           if suspicious == 1 else
                           f"{suspicious} vendors flagged this IP as suspicious")
                cache[ip] = ("suspicious", comment)
            elif harmless > 0:
                comment = (f"{harmless} vendor reported this IP as benign"
                           if harmless == 1 else
                           f"{harmless} vendors reported this IP as benign")
                cache[ip] = ("benign", comment)
            else:
                cache[ip] = ("unchecked", "IP will need to be investigated manually")
        else:
            cache[ip] = ("unchecked", "IP will need to be investigated manually")
    except Exception as e:
        print(f"[red]Error querying VirusTotal for IP {ip}: {e}[/red]")
        cache[ip] = ("unchecked", "IP will need to be investigated manually")

    return cache[ip]

def analyze_ips(msg_obj, api_key):
    ip_list = extract_ips_from_headers(msg_obj)
    if not ip_list:
        print("[yellow]No IP addresses found in this email.[/yellow]\n")
        return []

    cache = {}

    ips_with_data = []
    for ip in ip_list:
        verdict, comment = check_ip_virustotal(ip, api_key, cache)
        country = get_geoip_country(ip)

        if is_private_ip(ip):
            country = "Private"
        elif country == "Undefined":
            country = "Undefined"

        ips_with_data.append((ip, country, verdict, comment))

    # Sort order by verdict priority
    verdict_priority = {"malicious": 0, "suspicious": 1, "unchecked": 2, "benign": 3}

    # Sort IPs by verdict, then put Undefined countries last, then by IP string
    ips_with_data.sort(key=lambda x: (
        verdict_priority.get(x[2], 4),
        x[1] == "Undefined",
        x[0]
    ))

    for ip, country, verdict, comment in ips_with_data:
        if verdict == "malicious":
            verdict_text = "[red]MALICIOUS[/red]"
        elif verdict == "suspicious":
            verdict_text = "[orange3]SUSPICIOUS[/orange3]"
        elif verdict == "benign":
            verdict_text = "[green]BENIGN[/green]"
        elif verdict == "unchecked":
            verdict_text = "[orange3]UNCHECKED[/orange3]"
        else:
            verdict_text = "[orange3]UNKNOWN[/orange3]"

        print(f"IP: [yellow]{ip}[/yellow] ({country}) - Verdict: {verdict_text} ({comment})")

    return []
