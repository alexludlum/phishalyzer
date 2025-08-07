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

def safe_extract_ips_from_body(msg_obj):
    """NEW: Extract IP addresses from email body content including HTML"""
    try:
        if not msg_obj:
            return []
        
        body_content = ""
        
        # Extract both plain text and HTML content
        if hasattr(msg_obj, 'is_multipart') and msg_obj.is_multipart():
            for part in msg_obj.walk():
                try:
                    if part.get_content_type() == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_content = payload.decode('utf-8', errors='ignore')
                            # Strip HTML tags but keep the text content
                            text_content = re.sub(r'<[^>]+>', ' ', html_content)
                            body_content += text_content + " "
                    
                    elif part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            plain_content = payload.decode('utf-8', errors='ignore')
                            body_content += plain_content + " "
                            
                except Exception:
                    continue
        else:
            # Single part message
            try:
                payload = msg_obj.get_payload(decode=True)
                if payload:
                    if isinstance(payload, bytes):
                        content = payload.decode('utf-8', errors='ignore')
                    else:
                        content = str(payload)
                    
                    # If it contains HTML tags, strip them
                    if '<' in content and '>' in content:
                        content = re.sub(r'<[^>]+>', ' ', content)
                    
                    body_content += content
            except Exception:
                try:
                    # Fallback to non-decoded payload
                    payload = msg_obj.get_payload()
                    if payload:
                        body_content = str(payload)
                except Exception:
                    body_content = ""
        
        # Extract IPs using regex
        ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        
        try:
            ips = list(set(re.findall(ip_regex, body_content)))
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Warning: Error extracting IPs from body: {e}", "warning")
            else:
                print(f"Warning: Error extracting IPs from body: {e}")
            return []

        # Filter out IP-like strings with leading zeros and validate ranges
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
            print_status(f"Error extracting IPs from body: {e}", "error")
        else:
            print(f"Error extracting IPs from body: {e}")
        return []

def safe_extract_ips_from_email_complete(msg_obj):
    """NEW: Extract IP addresses from BOTH headers AND body content"""
    try:
        all_ips = []
        
        # 1. Extract from headers (existing logic)
        header_ips = safe_extract_ips_from_headers(msg_obj)
        all_ips.extend(header_ips)
        
        # 2. NEW: Extract from email body
        body_ips = safe_extract_ips_from_body(msg_obj)
        all_ips.extend(body_ips)
        
        # Remove duplicates and return
        return list(set(all_ips))
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error in complete IP extraction: {e}", "error")
        else:
            print(f"Error in complete IP extraction: {e}")
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

def extract_country_from_vt_response(vt_response_data):
    """Extract country from existing VirusTotal response."""
    try:
        if not vt_response_data:
            return "Undefined"
        
        country = vt_response_data.get("data", {}).get("attributes", {}).get("country", "")
        if country:
            return country
        
        # Try alternative location fields
        as_owner = vt_response_data.get("data", {}).get("attributes", {}).get("as_owner", "")
        if as_owner and any(country_indicator in as_owner.upper() for country_indicator in ["US", "UNITED STATES", "CANADA", "UK"]):
            return "Network Provider Info Available"
        
        return "Undefined"
    except Exception:
        return "Undefined"

def safe_virustotal_request(url, headers, original_item):
    """Safely make VirusTotal request with retry logic."""
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            return response
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES - 1:
                escaped_item = output.escape(str(original_item)) if COMPATIBLE_OUTPUT else str(original_item)
                if COMPATIBLE_OUTPUT:
                    print_status(f"Timeout for {escaped_item}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})", "warning")
                else:
                    print(f"Timeout for {escaped_item}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(2)
            else:
                escaped_item = output.escape(str(original_item)) if COMPATIBLE_OUTPUT else str(original_item)
                if COMPATIBLE_OUTPUT:
                    print_status(f"Final timeout for {escaped_item} after {MAX_RETRIES} attempts", "warning")
                else:
                    print(f"Final timeout for {escaped_item} after {MAX_RETRIES} attempts")
                return None
        except requests.exceptions.ConnectionError:
            if attempt < MAX_RETRIES - 1:
                escaped_item = output.escape(str(original_item)) if COMPATIBLE_OUTPUT else str(original_item)
                if COMPATIBLE_OUTPUT:
                    print_status(f"Connection error for {escaped_item}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})", "warning")
                else:
                    print(f"Connection error for {escaped_item}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(2)
            else:
                escaped_item = output.escape(str(original_item)) if COMPATIBLE_OUTPUT else str(original_item)
                if COMPATIBLE_OUTPUT:
                    print_status(f"Final connection error for {escaped_item} after {MAX_RETRIES} attempts", "warning")
                else:
                    print(f"Final connection error for {escaped_item} after {MAX_RETRIES} attempts")
                return None
        except Exception as e:
            escaped_item = output.escape(str(original_item)) if COMPATIBLE_OUTPUT else str(original_item)
            if COMPATIBLE_OUTPUT:
                print_status(f"Unexpected error querying {escaped_item}: {e}", "error")
            else:
                print(f"Unexpected error querying {escaped_item}: {e}")
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

def check_ip_virustotal_with_country(ip, api_key, cache):
    """Check IP against VirusTotal and extract both reputation and country from single API call."""
    if not ip:
        return ("unchecked", "No IP provided", "Undefined")
    
    # Check cache first (now storing 3-tuple: verdict, comment, country)
    cache_key = f"{ip}_full"
    if cache_key in cache:
        return cache[cache_key]

    # Check if private IP
    try:
        if safe_is_private_ip(ip):
            result = ("unchecked", "IP is private", "Private")
            cache[cache_key] = result
            return result
    except Exception:
        pass

    # Check if API key provided
    if not api_key:
        result = ("unchecked", "IP will need to be investigated manually", "No API Key")
        cache[cache_key] = result
        return result

    # Validate API key format
    try:
        if len(api_key.strip()) < 10:
            result = ("unchecked", "Invalid API key format", "Invalid API")
            cache[cache_key] = result
            return result
    except Exception:
        result = ("unchecked", "API key validation error", "API Error")
        cache[cache_key] = result
        return result

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key.strip()}

    try:
        response = safe_virustotal_request(url, headers, ip)
        
        if response is None:
            result = ("unchecked", "Network error - could not reach VirusTotal", "Network Error")
            cache[cache_key] = result
            return result
        
        if response.status_code == 429:
            action = safe_handle_rate_limit(ip)
            if action == "wait":
                # Try again after waiting
                response = safe_virustotal_request(url, headers, ip)
                if response is None or response.status_code == 429:
                    result = ("unchecked", "Rate limit persists", "Rate Limited")
                    cache[cache_key] = result
                    return result
            else:  # skip
                result = ("unchecked", "Skipped due to rate limit", "Skipped")
                cache[cache_key] = result
                return result

        if response.status_code == 200:
            try:
                data = response.json()
                
                # Extract reputation data
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                
                # Extract country from same response - NO ADDITIONAL API CALL!
                country = extract_country_from_vt_response(data)

                # Determine verdict
                if malicious > 0:
                    comment = (f"{malicious} vendor flagged this IP as malicious"
                               if malicious == 1 else
                               f"{malicious} vendors flagged this IP as malicious")
                    verdict = "malicious"
                elif suspicious > 0:
                    comment = (f"{suspicious} vendor flagged this IP as suspicious"
                               if suspicious == 1 else
                               f"{suspicious} vendors flagged this IP as suspicious")
                    verdict = "suspicious"
                elif harmless > 0:
                    comment = (f"{harmless} vendor reported this IP as benign"
                               if harmless == 1 else
                               f"{harmless} vendors reported this IP as benign")
                    verdict = "benign"
                else:
                    comment = "No analysis results available"
                    verdict = "unchecked"
                
                result = (verdict, comment, country)
                cache[cache_key] = result
                return result
                    
            except ValueError as e:
                result = ("unchecked", f"Invalid JSON response: {e}", "JSON Error")
                cache[cache_key] = result
                return result
            except KeyError as e:
                result = ("unchecked", f"Unexpected response format: {e}", "Format Error")
                cache[cache_key] = result
                return result
            except Exception as e:
                result = ("unchecked", f"Response parsing error: {e}", "Parse Error")
                cache[cache_key] = result
                return result
                
        elif response.status_code == 401:
            result = ("unchecked", "Invalid API key", "Auth Error")
            cache[cache_key] = result
            return result
        elif response.status_code == 403:
            result = ("unchecked", "API access forbidden", "Access Denied")
            cache[cache_key] = result
            return result
        elif response.status_code == 404:
            result = ("unchecked", "IP not found in VirusTotal", "Not Found")
            cache[cache_key] = result
            return result
        else:
            result = ("unchecked", f"HTTP {response.status_code}", "HTTP Error")
            cache[cache_key] = result
            return result
            
    except Exception as e:
        escaped_ip = output.escape(ip) if COMPATIBLE_OUTPUT else ip
        if COMPATIBLE_OUTPUT:
            print_status(f"Error querying VirusTotal for IP {escaped_ip}: {e}", "error")
        else:
            print(f"Error querying VirusTotal for IP {escaped_ip}: {e}")
        result = ("unchecked", "Unexpected error during check", "Error")
        cache[cache_key] = result
        return result

def analyze_ips(msg_obj, api_key):
    """Analyze IPs from both email headers AND body content with comprehensive error handling."""
    try:
        ip_list = safe_extract_ips_from_email_complete(msg_obj)
        
        if not ip_list:
            if COMPATIBLE_OUTPUT:
                print_status("IP address analysis completed successfully.", "success")
                output.print("[green]No IP addresses were detected in the email.[/green]")
                output.print("This indicates:")
                output.print("- Clean email headers and body")
                output.print("- No embedded IP addresses found")
                output.print("- Network infrastructure details may have been sanitized")
            else:
                print("IP address analysis completed successfully.")
                print("No IP addresses were detected in the email.")
                print("This indicates:")
                print("- Clean email headers and body")
                print("- No embedded IP addresses found") 
                print("- Network infrastructure details may have been sanitized")
            return []
        
        cache = {}
        ips_with_data = []
        
        for ip in ip_list:
            try:
                # Single API call gets both reputation and country
                verdict, comment, country = check_ip_virustotal_with_country(ip, api_key, cache)
                
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