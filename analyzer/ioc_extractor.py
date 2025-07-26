# analyzer/ioc_extractor.py

import re
import shutil
import requests
from rich import print
from rich.text import Text
from rich.console import Console

console = Console()

IP_PATTERN = re.compile(
    r'\b('
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
    r')\b'
)


def print_centered_header(text):
    width = shutil.get_terminal_size().columns
    header_line = "=" * width
    padding = (width - len(text)) // 2
    print(header_line)
    print(" " * padding + text)
    print(header_line + "\n")


def analyze_ips(msg_obj, vt_api_key=None, suppress_header=False):
    if not suppress_header:
        print_centered_header("EMAIL HEADER ANALYSIS".replace("EMAIL HEADER ANALYSIS", "IOC IP ADDRESS ANALYSIS"))

    text_to_search = ""
    for header, value in msg_obj.items():
        text_to_search += f"{header}: {value}\n"

    ips = set(m.group(0) for m in IP_PATTERN.finditer(text_to_search))

    if not ips:
        print("No IP addresses found in this email.\n")
        return []

    results = []
    checked_ips = {}

    if not vt_api_key:
        print("[yellow]No VirusTotal API key provided. IPs will need to be investigated manually.[/yellow]\n")

    for ip in ips:
        if vt_api_key:
            if ip in checked_ips:
                vt_data = checked_ips[ip]["vt_data"]
                verdict = checked_ips[ip]["verdict"]
            else:
                vt_data = query_virustotal_ip(ip, vt_api_key)
                verdict = parse_vt_ip_verdict(vt_data)
                checked_ips[ip] = {
                    "vt_data": vt_data,
                    "verdict": verdict
                }

            if verdict == "benign":
                verdict_text = Text("BENIGN", style="green")
            elif verdict == "suspicious":
                verdict_text = Text("SUSPICIOUS", style="orange3")
            elif verdict == "malicious":
                verdict_text = Text("MALICIOUS", style="red", justify="left", no_wrap=True)
            else:
                verdict_text = Text("UNKNOWN", style="yellow")

        else:
            verdict = "UNCHECKED"
            vt_data = None
            verdict_text = Text("UNCHECKED", style="orange3")

        console.print("IP:", f"[yellow]{ip}[/yellow]", "- Verdict:", verdict_text)

        results.append({
            "ip": ip,
            "vt_data": vt_data,
            "verdict": verdict
        })

    return results


def query_virustotal_ip(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"[orange3]Warning: VT API returned status {resp.status_code} for IP {ip}[/orange3]")
            return None
    except Exception as e:
        print(f"[red]Error querying VT for IP {ip}: {e}[/red]")
        return None


def parse_vt_ip_verdict(vt_data):
    if not vt_data:
        return "unknown"
    stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    if not stats:
        return "unknown"
    if stats.get("malicious", 0) > 0:
        return "malicious"
    elif stats.get("suspicious", 0) > 0:
        return "suspicious"
    else:
        return "benign"
