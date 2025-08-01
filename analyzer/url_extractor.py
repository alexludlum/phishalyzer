import re
import time
import requests
import base64
from rich import print
from urllib.parse import urlparse
from . import defanger

# Network request timeout settings
REQUEST_TIMEOUT = 10
MAX_RETRIES = 3

def safe_extract_urls_from_headers(msg_obj):
    """Safely extract URLs from email headers with error handling."""
    try:
        if not msg_obj:
            return []
        
        # Regex to capture URLs, including http/https and www prefixed
        url_regex = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
        
        try:
            headers = str(msg_obj)
        except Exception as e:
            print(f"[yellow]Warning: Could not convert message to string: {e}[/yellow]")
            return []
        
        try:
            urls = list(set(re.findall(url_regex, headers)))
        except Exception as e:
            print(f"[yellow]Warning: Error extracting URLs: {e}[/yellow]")
            return []

        # Validate and clean URLs
        valid_urls = []
        for url in urls:
            try:
                # Basic URL validation and cleaning
                url = url.strip()
                if len(url) > 2000:  # Skip extremely long URLs
                    continue
                if url and not url.isspace():
                    valid_urls.append(url)
            except Exception:
                continue
        
        return valid_urls
        
    except Exception as e:
        print(f"[red]Error in URL extraction: {e}[/red]")
        return []

def safe_url_to_id(url):
    """Safely convert URL to VirusTotal ID with error handling."""
    try:
        if not url or not isinstance(url, str):
            return None
        
        # Ensure URL is properly encoded
        url_bytes = url.encode('utf-8')
        b64 = base64.urlsafe_b64encode(url_bytes).decode().strip("=")
        return b64
    except Exception as e:
        print(f"[yellow]Error encoding URL {url}: {e}[/yellow]")
        return None

def safe_virustotal_request(url, headers, original_url):
    """Safely make VirusTotal request with retry logic."""
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            return response
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES - 1:
                print(f"[yellow]Timeout for {original_url}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})[/yellow]")
                time.sleep(2)
            else:
                print(f"[yellow]Final timeout for {original_url} after {MAX_RETRIES} attempts[/yellow]")
                return None
        except requests.exceptions.ConnectionError:
            if attempt < MAX_RETRIES - 1:
                print(f"[yellow]Connection error for {original_url}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})[/yellow]")
                time.sleep(2)
            else:
                print(f"[yellow]Final connection error for {original_url} after {MAX_RETRIES} attempts[/yellow]")
                return None
        except Exception as e:
            print(f"[red]Unexpected error querying {original_url}: {e}[/red]")
            return None
    
    return None

def safe_handle_rate_limit(url):
    """Safely handle VirusTotal rate limiting with user choice."""
    try:
        while True:
            try:
                choice = input(
                    "[yellow]VirusTotal API rate limit reached.[/yellow]\n"
                    "Type 'wait' to wait 60 seconds, or 'skip' to proceed without checking: "
                ).strip().lower()
                
                if choice == "wait":
                    print("Waiting 60 seconds...")
                    time.sleep(60)
                    return "wait"
                elif choice == "skip":
                    return "skip"
                else:
                    print("Invalid input. Please type 'wait' or 'skip'.")
            except (KeyboardInterrupt, EOFError):
                print("\nSkipping due to user interruption.")
                return "skip"
            except Exception as e:
                print(f"[red]Input error: {e}[/red]")
                return "skip"
    except Exception:
        return "skip"

def check_url_virustotal(url, api_key, cache):
    """Check URL against VirusTotal with comprehensive error handling."""
    if not url:
        return ("unchecked", "No URL provided")
    
    # Check cache first
    if url in cache:
        return cache[url]

    # Check if API key provided
    if not api_key:
        cache[url] = ("unchecked", "URL will need to be investigated manually")
        return cache[url]

    # Validate API key format
    try:
        if len(api_key.strip()) < 10:
            cache[url] = ("unchecked", "Invalid API key format")
            return cache[url]
    except Exception:
        cache[url] = ("unchecked", "API key validation error")
        return cache[url]

    # Convert URL to VirusTotal ID
    url_id = safe_url_to_id(url)
    if not url_id:
        cache[url] = ("unchecked", "Could not encode URL for VirusTotal")
        return cache[url]

    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key.strip()}

    try:
        response = safe_virustotal_request(api_url, headers, url)
        
        if response is None:
            cache[url] = ("unchecked", "Network error - could not reach VirusTotal")
            return cache[url]
        
        if response.status_code == 429:
            action = safe_handle_rate_limit(url)
            if action == "wait":
                # Try again after waiting
                response = safe_virustotal_request(api_url, headers, url)
                if response is None or response.status_code == 429:
                    cache[url] = ("unchecked", "Rate limit persists")
                    return cache[url]
            else:  # skip
                cache[url] = ("unchecked", "Skipped due to rate limit")
                return cache[url]

        if response.status_code == 200:
            try:
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
                    cache[url] = ("unchecked", "No analysis results available")
                    
            except ValueError as e:
                cache[url] = ("unchecked", f"Invalid JSON response: {e}")
            except KeyError as e:
                cache[url] = ("unchecked", f"Unexpected response format: {e}")
            except Exception as e:
                cache[url] = ("unchecked", f"Response parsing error: {e}")
                
        elif response.status_code == 401:
            cache[url] = ("unchecked", "Invalid API key")
        elif response.status_code == 403:
            cache[url] = ("unchecked", "API access forbidden")
        elif response.status_code == 404:
            cache[url] = ("unchecked", "URL not found in VirusTotal")
        else:
            cache[url] = ("unchecked", f"HTTP {response.status_code}")
            
    except Exception as e:
        print(f"[red]Error querying VirusTotal for URL {url}: {e}[/red]")
        cache[url] = ("unchecked", "Unexpected error during check")

    return cache[url]

def safe_get_domain(url):
    """Safely extract domain from URL for sorting."""
    try:
        if not url or not isinstance(url, str):
            return ""
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower() if parsed.netloc else url.lower()
        return domain
    except Exception:
        return str(url).lower()

def analyze_urls(msg_obj, api_key):
    """Analyze URLs from email headers with comprehensive error handling."""
    try:
        url_list = safe_extract_urls_from_headers(msg_obj)
        
        if not url_list:
            print("[yellow]No URLs found in this email.[/yellow]")
            print("[yellow]Please verify manually as URLs might be obfuscated or embedded within attachments.[/yellow]\n")
            return []
        
        cache = {}
        results = []

        for url in url_list:
            try:
                verdict, comment = check_url_virustotal(url, api_key, cache)
                results.append((url, verdict, comment))
                
            except Exception as e:
                print(f"[red]Error processing URL {url}: {e}[/red]")
                results.append((url, "unchecked", f"Processing error: {e}"))

        # Sort results safely
        try:
            sort_order = {"malicious": 0, "suspicious": 1, "unchecked": 2, "benign": 3}
            results.sort(key=lambda x: (sort_order.get(x[1], 4), safe_get_domain(x[0])))
        except Exception as e:
            print(f"[yellow]Warning: Could not sort results: {e}[/yellow]")

        # Display results
        try:
            for url, verdict, comment in results:
                try:
                    # Apply defanging if enabled
                    display_url = defanger.defang_url(url) if defanger.should_defang() else url
                    
                    if verdict == "malicious":
                        verdict_text = "[red]MALICIOUS[/red]"
                    elif verdict == "unchecked":
                        verdict_text = "[orange3]UNCHECKED[/orange3]"
                    elif verdict == "benign":
                        verdict_text = "[green]BENIGN[/green]"
                    else:
                        verdict_text = "[orange3]UNKNOWN[/orange3]"

                    print(f"URL: [yellow]{display_url}[/yellow] - Verdict: {verdict_text} ({comment})")
                    
                except Exception as e:
                    print(f"Error displaying result for {url}: {e}")
                    
        except Exception as e:
            print(f"[red]Error displaying URL analysis results: {e}[/red]")

        return results

    except Exception as e:
        print(f"[red]Critical error in URL analysis: {e}[/red]")
        print("[yellow]URL analysis could not be completed.[/yellow]")
        return []