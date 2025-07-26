import re
import time
import requests
from rich import print
from urllib.parse import urlparse

def print_centered_header(title: str):
    width = 80
    print("=" * width)
    print(title.center(width))
    print("=" * width + "\n")

def extract_urls_from_headers(msg_obj):
    # Regex to capture URLs, including http/https and www prefixed
    url_regex = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
    headers = str(msg_obj)
    urls = list(set(re.findall(url_regex, headers)))
    return urls

def check_url_virustotal(url, api_key, cache):
    if url in cache:
        return cache[url]

    if not api_key:
        cache[url] = ("unchecked", "URL will need to be investigated manually")
        return cache[url]

    import base64
    def url_to_id(url):
        b64 = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return b64

    url_id = url_to_id(url)
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 429:
            while True:
                choice = input(
                    "[yellow]VirusTotal API rate limit reached.[/yellow]\n"
                    "Type 'wait' to wait 60 seconds, or 'skip' to proceed without checking: "
                ).strip().lower()
                if choice == "wait":
                    print("Waiting 60 seconds...")
                    time.sleep(60)
                    response = requests.get(api_url, headers=headers)
                    if response.status_code != 429:
                        break
                elif choice == "skip":
                    cache[url] = ("unchecked", "URL will need to be investigated manually")
                    return cache[url]
                else:
                    print("Invalid input. Please type 'wait' or 'skip'.")

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            if malicious > 0:
                comment = (f"{malicious} vendor flagged this URL as malicious"
                           if malicious == 1 else
                           f"{malicious} vendors flagged this URL as malicious")
                cache[url] = ("malicious", comment)
            elif suspicious > 0:
                comment = (f"{suspicious} vendor flagged this URL as suspicious"
                           if suspicious == 1 else
                           f"{suspicious} vendors flagged this URL as suspicious")
                cache[url] = ("suspicious", comment)
            elif harmless > 0:
                comment = (f"{harmless} vendor reported this URL as benign"
                           if harmless == 1 else
                           f"{harmless} vendors reported this URL as benign")
                cache[url] = ("benign", comment)
            else:
                cache[url] = ("unchecked", "URL will need to be investigated manually")
        else:
            cache[url] = ("unchecked", "URL will need to be investigated manually")
    except Exception as e:
        print(f"[red]Error querying VirusTotal for URL {url}: {e}[/red]")
        cache[url] = ("unchecked", "URL will need to be investigated manually")

    return cache[url]

def analyze_urls(msg_obj, api_key):
    print_centered_header("URL ANALYSIS")
    url_list = extract_urls_from_headers(msg_obj)
    if not url_list:
        print("[yellow]No URLs found in this email.[/yellow]")
        print("[yellow]Please verify manually as URLs might be obfuscated or embedded within attachments.[/yellow]\n")
        return []

    cache = {}
    results = []

    for url in url_list:
        verdict, comment = check_url_virustotal(url, api_key, cache)
        results.append((url, verdict, comment))

    def get_domain(url):
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return url.lower()

    sort_order = {"malicious": 0, "unchecked": 1, "benign": 2}
    results.sort(key=lambda x: (sort_order.get(x[1], 3), get_domain(x[0])))

    for url, verdict, comment in results:
        if verdict == "malicious":
            verdict_text = "[red]MALICIOUS[/red]"
        elif verdict == "unchecked":
            verdict_text = "[orange3]UNCHECKED[/orange3]"
        elif verdict == "benign":
            verdict_text = "[green]BENIGN[/green]"
        else:
            verdict_text = "[orange3]UNKNOWN[/orange3]"

        print(f"URL: [yellow]{url}[/yellow] - Verdict: {verdict_text} ({comment})")

    return []
