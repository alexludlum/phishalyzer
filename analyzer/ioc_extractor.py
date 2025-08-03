import re
import time
import requests
import ipaddress

# Import compatible output system
try:
    from .compatible_output import output, print_status, print_ip_result
    COMPATIBLE_OUTPUT = True
except ImportError:
    COMPATIBLE_OUTPUT = False

from . import defanger

# Network request timeout settings
REQUEST_TIMEOUT = 10
MAX_RETRIES = 3

def safe_extract_ips_from_headers(msg_obj):
    """Safely extract IPs from email headers with error handling."""
    try:
        if not msg_obj:
            return []
        
        ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        
        try:
            headers = str(msg_obj)
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Warning: Could not convert message to string: {e}", "warning")
            else:
                print(f"Warning: Could not convert message to string: {e}")
            return []
        
        try:
            ips = list(set(re.findall(ip_regex, headers)))
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Warning: Error extracting IPs: {e}", "warning")
            else:
                print(f"Warning: Error extracting IPs: {e}")
            return []

        # Filter out IP-like strings with leading zeros (except single '0')
        def valid_ip(ip):
            try:
                parts = ip.split('.')
                for p in parts:
                    if len(p) > 1 and p.startswith('0'):
                        return False
                    # Validate each octet is 0-255
                    if not (0 <= int(p) <= 255):
                        return False
                return True
            except (ValueError, AttributeError):
                return False

        valid_ips = []
        for ip in ips:
            try:
                if valid_ip(ip):
                    valid_ips.append(ip)
            except Exception:
                continue
        
        return valid_ips
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error in IP extraction: {e}", "error")
        else:
            print(f"Error in IP extraction: {e}")
        return []

def safe_is_private_ip(ip):
    """Safely check if IP is private with error handling."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except (ValueError, ipaddress.AddressValueError):
        return False
    except Exception:
        return False

def safe_get_geoip_country(ip):
    """Safely get country for IP with error handling and timeout."""
    if not ip:
        return "Undefined"
    
    try:
        # Check if it's a private IP first
        if safe_is_private_ip(ip):
            return "Private"
        
        response = requests.get(
            f"https://ipapi.co/{ip}/country_name/", 
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            country = response.text.strip()
            if country and country.lower() not in ['undefined', 'none', '']:
                return country
        elif response.status_code == 429:
            escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
            if COMPATIBLE_OUTPUT:
                print_status(f"Rate limited for GeoIP lookup of {escaped_ip}", "warning")
            else:
                print(f"Rate limited for GeoIP lookup of {escaped_ip}")
            return "Rate Limited"
        
    except requests.exceptions.Timeout:
        escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
        if COMPATIBLE_OUTPUT:
            print_status(f"Timeout getting country for {escaped_ip}", "warning")
        else:
            print(f"Timeout getting country for {escaped_ip}")
        return "Timeout"
    except requests.exceptions.ConnectionError:
        escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
        if COMPATIBLE_OUTPUT:
            print_status(f"Connection error getting country for {escaped_ip}", "warning")
        else:
            print(f"Connection error getting country for {escaped_ip}")
        return "No Connection"
    except requests.exceptions.RequestException as e:
        escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
        if COMPATIBLE_OUTPUT:
            print_status(f"Request error for {escaped_ip}: {e}", "warning")
        else:
            print(f"Request error for {escaped_ip}: {e}")
        return "Request Error"
    except Exception as e:
        escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
        if COMPATIBLE_OUTPUT:
            print_status(f"Unexpected error getting country for {escaped_ip}: {e}", "warning")
        else:
            print(f"Unexpected error getting country for {escaped_ip}: {e}")
        return "Error"
    
    return "Undefined"

def safe_virustotal_request(url, headers, ip):
    """Safely make VirusTotal request with retry logic."""
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            return response
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES - 1:
                escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
                if COMPATIBLE_OUTPUT:
                    print_status(f"Timeout for {escaped_ip}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})", "warning")
                else:
                    print(f"Timeout for {escaped_ip}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(2)
            else:
                escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
                if COMPATIBLE_OUTPUT:
                    print_status(f"Final timeout for {escaped_ip} after {MAX_RETRIES} attempts", "warning")
                else:
                    print(f"Final timeout for {escaped_ip} after {MAX_RETRIES} attempts")
                return None
        except requests.exceptions.ConnectionError:
            if attempt < MAX_RETRIES - 1:
                escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
                if COMPATIBLE_OUTPUT:
                    print_status(f"Connection error for {escaped_ip}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})", "warning")
                else:
                    print(f"Connection error for {escaped_ip}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(2)
            else:
                escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
                if COMPATIBLE_OUTPUT:
                    print_status(f"Final connection error for {escaped_ip} after {MAX_RETRIES} attempts", "warning")
                else:
                    print(f"Final connection error for {escaped_ip} after {MAX_RETRIES} attempts")
                return None
        except Exception as e:
            escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
            if COMPATIBLE_OUTPUT:
                print_status(f"Unexpected error querying {escaped_ip}: {e}", "error")
            else:
                print(f"Unexpected error querying {escaped_ip}: {e}")
            return None
    
    return None

def safe_handle_rate_limit(ip):
    """Safely handle VirusTotal rate limiting with user choice."""
    try:
        while True:
            try:
                choice = input(
                    "VirusTotal API rate limit reached.\n"
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
                if COMPATIBLE_OUTPUT:
                    print_status(f"Input error: {e}", "error")
                else:
                    print(f"Input error: {e}")
                return "skip"
    except Exception:
        return "skip"

def check_ip_virustotal(ip, api_key, cache):
    """Check IP against VirusTotal with comprehensive error handling."""
    if not ip:
        return ("unchecked", "No IP provided")
    
    # Check cache first
    if ip in cache:
        return cache[ip]

    # Check if private IP
    try:
        if safe_is_private_ip(ip):
            cache[ip] = ("unchecked", "IP is private")
            return cache[ip]
    except Exception:
        pass

    # Check if API key provided
    if not api_key:
        cache[ip] = ("unchecked", "IP will need to be investigated manually")
        return cache[ip]

    # Validate API key format
    try:
        if len(api_key.strip()) < 10:
            cache[ip] = ("unchecked", "Invalid API key format")
            return cache[ip]
    except Exception:
        cache[ip] = ("unchecked", "API key validation error")
        return cache[ip]

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key.strip()}

    try:
        response = safe_virustotal_request(url, headers, ip)
        
        if response is None:
            cache[ip] = ("unchecked", "Network error - could not reach VirusTotal")
            return cache[ip]
        
        if response.status_code == 429:
            action = safe_handle_rate_limit(ip)
            if action == "wait":
                # Try again after waiting
                response = safe_virustotal_request(url, headers, ip)
                if response is None or response.status_code == 429:
                    cache[ip] = ("unchecked", "Rate limit persists")
                    return cache[ip]
            else:  # skip
                cache[ip] = ("unchecked", "Skipped due to rate limit")
                return cache[ip]

        if response.status_code == 200:
            try:
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
                    cache[ip] = ("unchecked", "No analysis results available")
                    
            except ValueError as e:
                cache[ip] = ("unchecked", f"Invalid JSON response: {e}")
            except KeyError as e:
                cache[ip] = ("unchecked", f"Unexpected response format: {e}")
            except Exception as e:
                cache[ip] = ("unchecked", f"Response parsing error: {e}")
                
        elif response.status_code == 401:
            cache[ip] = ("unchecked", "Invalid API key")
        elif response.status_code == 403:
            cache[ip] = ("unchecked", "API access forbidden")
        elif response.status_code == 404:
            cache[ip] = ("unchecked", "IP not found in VirusTotal")
        else:
            cache[ip] = ("unchecked", f"HTTP {response.status_code}")
            
    except Exception as e:
        escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
        if COMPATIBLE_OUTPUT:
            print_status(f"Error querying VirusTotal for IP {escaped_ip}: {e}", "error")
        else:
            print(f"Error querying VirusTotal for IP {escaped_ip}: {e}")
        cache[ip] = ("unchecked", "Unexpected error during check")

    return cache[ip]

def analyze_ips(msg_obj, api_key):
    """Analyze IPs from email headers with comprehensive error handling."""
    try:
        ip_list = safe_extract_ips_from_headers(msg_obj)
        
        if not ip_list:
            if COMPATIBLE_OUTPUT:
                print_status("No IP addresses found in this email.", "warning")
            else:
                print("No IP addresses found in this email.")
            return []
        
        cache = {}
        ips_with_data = []
        
        for ip in ip_list:
            try:
                verdict, comment = check_ip_virustotal(ip, api_key, cache)
                country = safe_get_geoip_country(ip)

                if safe_is_private_ip(ip):
                    country = "Private"
                elif country == "Undefined":
                    country = "Undefined"

                ips_with_data.append((ip, country, verdict, comment))
                
            except Exception as e:
                escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error processing IP {escaped_ip}: {e}", "error")
                else:
                    print(f"Error processing IP {escaped_ip}: {e}")
                ips_with_data.append((ip, "Error", "unchecked", f"Processing error: {e}"))

        # Sort results safely
        try:
            verdict_priority = {"malicious": 0, "suspicious": 1, "unchecked": 2, "benign": 3}

            ips_with_data.sort(key=lambda x: (
                verdict_priority.get(x[2], 4),
                x[1] == "Undefined",
                x[0]
            ))
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Warning: Could not sort results: {e}", "warning")
            else:
                print(f"Warning: Could not sort results: {e}")

        # Display results
        try:
            for ip, country, verdict, comment in ips_with_data:
                try:
                    if COMPATIBLE_OUTPUT:
                        # Use the defang function for IP display
                        def defang_func(ip_addr):
                            return defanger.defang_ip(ip_addr) if defanger.should_defang() else ip_addr
                        
                        print_ip_result(ip, country, verdict, comment, defang_func)
                    else:
                        # Simple output for non-compatible terminals
                        display_ip = defanger.defang_ip(ip) if defanger.should_defang() else ip
                        print(f"IP: {display_ip} ({country}) - Verdict: {verdict.upper()} ({comment})")
                    
                except Exception as e:
                    escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
                    print(f"Error displaying result for {escaped_ip}: {e}")
                    
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error displaying IP analysis results: {e}", "error")
            else:
                print(f"Error displaying IP analysis results: {e}")

        return ips_with_data

    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Critical error in IP analysis: {e}", "error")
            print_status("IP analysis could not be completed.", "warning")
        else:
            print(f"Critical error in IP analysis: {e}")
            print("IP analysis could not be completed.")
        return []