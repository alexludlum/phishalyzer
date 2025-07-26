import re
import time
import requests
import ipaddress
from rich import print

def print_centered_header(title: str):
    width = 80
    print("=" * width)
    print(title.center(width))
    print("=" * width + "\n")

def extract_ips_from_headers(msg_obj):
    ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    headers = str(msg_obj)
    ips = list(set(re.findall(ip_regex, headers)))

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
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_geoip_country(ip):
    if is_private_ip(ip):
        return "Private"
    try:
        response = requests.get(f"https://ipapi.co/{ip}/country_name/", timeout=5)
        if response.status_code == 200:
            country = response.text.strip()
            if country:
                return country
    except Exception:
        pass
    return "unknown"

def check_ip_virustotal(ip, api_key, cache):
    if ip in cache:
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
            if stats.get("malicious", 0) > 0:
                cache[ip] = ("malicious", "one or more vendors reported this IP")
            elif stats.get("suspicious", 0) > 0:
                cache[ip] = ("suspicious", "some vendors flagged this IP")
            elif stats.get("harmless", 0) > 0:
                cache[ip] = ("benign", "this IP address has not been reported at this time")
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
    results = []

    for ip in ip_list:
        verdict, comment = check_ip_virustotal(ip, api_key, cache)
        country = get_geoip_country(ip)

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

        results.append((country, ip, verdict_text, comment))

    # Sort so that "Private" and "unknown" are last
    def sort_key(entry):
        country = entry[0].lower()
        if country in ("private", "unknown"):
            return (1, country)
        return (0, country)

    sorted_results = sorted(results, key=sort_key)

    for country, ip, verdict_text, comment in sorted_results:
        print(f"IP: [yellow]{ip}[/yellow] ({country}) - Verdict: {verdict_text} ({comment})")

    return []
