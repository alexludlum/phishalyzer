import re
import time
import requests
import base64
import os
from urllib.parse import urlparse
from collections import defaultdict

# Import universal output system
try:
    from .compatible_output import output, print_status
    COMPATIBLE_OUTPUT = True
except ImportError:
    COMPATIBLE_OUTPUT = False

from . import defanger

# Network request timeout settings
REQUEST_TIMEOUT = 10
MAX_RETRIES = 3

def simple_defang(text):
    """Simple defanging function that actually works"""
    if not text or not isinstance(text, str):
        return text
    
    # Check if defanging is enabled
    try:
        OUTPUT_MODE_FILE = os.path.expanduser("~/.phishalyzer_output_mode")
        if os.path.exists(OUTPUT_MODE_FILE):
            with open(OUTPUT_MODE_FILE, "r", encoding='utf-8') as f:
                content = f.read().strip()
                if content != "defanged":
                    return text  # Don't defang if not in defanged mode
        else:
            return text  # No settings file, don't defang
    except:
        return text  # Error reading file, don't defang
    
    # Apply defanging
    result = text
    
    # Replace protocols
    result = result.replace('https://', 'https[:]//') 
    result = result.replace('http://', 'http[:]//') 
    result = result.replace('ftp://', 'ftp[:]//') 
    
    # Replace common TLDs and domains
    result = result.replace('.net', '[.]net')
    result = result.replace('.com', '[.]com')
    result = result.replace('.org', '[.]org')
    result = result.replace('.edu', '[.]edu')
    result = result.replace('.gov', '[.]gov')
    result = result.replace('.mil', '[.]mil')
    result = result.replace('.int', '[.]int')
    result = result.replace('.co.', '[.]co[.]')
    result = result.replace('.uk', '[.]uk')
    result = result.replace('.de', '[.]de')
    result = result.replace('.fr', '[.]fr')
    result = result.replace('.io', '[.]io')
    result = result.replace('.me', '[.]me')
    result = result.replace('.ru', '[.]ru')
    result = result.replace('.cn', '[.]cn')
    result = result.replace('.jp', '[.]jp')
    result = result.replace('.au', '[.]au')
    result = result.replace('.ca', '[.]ca')
    result = result.replace('.info', '[.]info')
    result = result.replace('.biz', '[.]biz')
    result = result.replace('.tv', '[.]tv')
    result = result.replace('.cc', '[.]cc')
    
    return result

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
            if COMPATIBLE_OUTPUT:
                print_status(f"Warning: Could not convert message to string: {e}", "warning")
            else:
                print(f"Warning: Could not convert message to string: {e}")
            return []
        
        try:
            urls = list(set(re.findall(url_regex, headers)))
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Warning: Error extracting URLs: {e}", "warning")
            else:
                print(f"Warning: Error extracting URLs: {e}")
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
        if COMPATIBLE_OUTPUT:
            print_status(f"Error in URL extraction: {e}", "error")
        else:
            print(f"Error in URL extraction: {e}")
        return []

def safe_extract_urls_from_body(msg_obj):
    """NEW: Extract URLs from email body content including HTML links"""
    try:
        if not msg_obj:
            return []
        
        body_content = ""
        found_urls = []
        
        # Extract both plain text and HTML content
        if hasattr(msg_obj, 'is_multipart') and msg_obj.is_multipart():
            for part in msg_obj.walk():
                try:
                    if part.get_content_type() == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_content = payload.decode('utf-8', errors='ignore')
                            
                            # Extract href URLs BEFORE stripping HTML - this is the key fix!
                            href_patterns = [
                                r'href=["\']([^"\']+)["\']',  # Standard href attributes
                                r'href=([^\s>]+)',           # href without quotes
                                r'action=["\']([^"\']+)["\']', # Form actions
                                r'src=["\']([^"\']+)["\']'    # Image/script sources
                            ]
                            
                            for pattern in href_patterns:
                                href_matches = re.findall(pattern, html_content, re.IGNORECASE)
                                for match in href_matches:
                                    # Filter out non-HTTP URLs (mailto:, javascript:, etc.)
                                    if match.startswith(('http://', 'https://', 'www.')):
                                        found_urls.append(match)
                            
                            # Also get the HTML content for direct URL matches
                            body_content += html_content + " "
                    
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
                        body_content = payload.decode('utf-8', errors='ignore')
                    else:
                        body_content = str(payload)
            except Exception:
                try:
                    # Fallback to non-decoded payload
                    payload = msg_obj.get_payload()
                    if payload:
                        body_content = str(payload)
                except Exception:
                    body_content = ""
        
        # Extract URLs using enhanced regex patterns
        url_patterns = [
            r'https?://[^\s<>"\']+',                    # Standard HTTP URLs
            r'www\.[^\s<>"\']+',                        # www domains
            r'onclick=["\']location\.href=["\']([^"\']+)["\']'  # JavaScript redirects
        ]
        
        for pattern in url_patterns:
            try:
                matches = re.findall(pattern, body_content, re.IGNORECASE)
                if isinstance(matches[0] if matches else None, tuple):
                    # Handle patterns that return groups
                    found_urls.extend([match for match in matches if isinstance(match, str)])
                else:
                    found_urls.extend(matches)
            except Exception:
                continue
        
        # Clean and validate URLs
        valid_urls = []
        for url in found_urls:
            try:
                url = url.strip()
                if len(url) > 2000:  # Skip extremely long URLs
                    continue
                if url and not url.isspace():
                    # Basic URL validation
                    if url.startswith(('http://', 'https://', 'www.')):
                        valid_urls.append(url)
            except Exception:
                continue
        
        return list(set(valid_urls))  # Remove duplicates
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error extracting URLs from body: {e}", "error")
        else:
            print(f"Error extracting URLs from body: {e}")
        return []

def safe_extract_urls_from_email_complete(msg_obj):
    """NEW: Extract URLs from BOTH headers AND body content"""
    try:
        all_urls = []
        
        # 1. Extract from headers (existing logic)
        header_urls = safe_extract_urls_from_headers(msg_obj)
        all_urls.extend(header_urls)
        
        # 2. NEW: Extract from email body
        body_urls = safe_extract_urls_from_body(msg_obj)
        all_urls.extend(body_urls)
        
        # Remove duplicates and return
        return list(set(all_urls))
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error in complete URL extraction: {e}", "error")
        else:
            print(f"Error in complete URL extraction: {e}")
        return []

def extract_domain(url):
    """Extract domain from URL for grouping with better handling of malformed URLs."""
    try:
        if not url or not isinstance(url, str):
            return "unknown"
        
        # Clean up the URL first
        clean_url = url.strip()
        
        # Handle URLs that end with = (likely truncated)
        if clean_url.endswith('='):
            # Try to find a reasonable domain boundary
            # Look for common patterns before the truncation
            if '//' in clean_url:
                try:
                    protocol_part, rest = clean_url.split('//', 1)
                    domain_part = rest.split('/')[0].split('?')[0].split('#')[0]
                    
                    # If domain part ends with =, it's likely truncated
                    if domain_part.endswith('='):
                        # Try to find the actual domain before truncation
                        if '.' in domain_part:
                            # Keep everything up to the last reasonable domain part
                            parts = domain_part.split('.')
                            # Find the last part that looks like a proper TLD
                            for i in range(len(parts) - 1, -1, -1):
                                if parts[i] and not parts[i].endswith('='):
                                    domain_part = '.'.join(parts[:i+1])
                                    break
                            else:
                                # All parts are malformed, use a generic name
                                return "truncated-urls"
                        else:
                            # No dots, likely completely malformed
                            return "malformed-urls"
                    
                    return domain_part.lower()
                except Exception:
                    return "malformed-urls"
        
        # Handle URLs without protocol
        if not clean_url.startswith(('http://', 'https://', 'ftp://')):
            if clean_url.startswith('www.'):
                clean_url = 'http://' + clean_url
            else:
                clean_url = 'http://' + clean_url
        
        try:
            parsed = urlparse(clean_url)
            domain = parsed.netloc.lower()
            
            # Remove www. prefix for grouping
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Additional validation - ensure domain looks reasonable
            if not domain or domain in ['', 'unknown']:
                return "malformed-urls"
            
            # Check for obviously malformed domains
            if domain.endswith('=') or len(domain) < 2:
                return "malformed-urls"
                
            return domain
            
        except Exception:
            return "malformed-urls"
            
    except Exception:
        return "malformed-urls"

def get_shortest_url_for_domain(urls):
    """Get the shortest (most representative) URL for a domain."""
    try:
        if not urls:
            return ""
        # Return the shortest URL as it's often the base/cleanest
        return min(urls, key=len)
    except Exception:
        return urls[0] if urls else ""

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
        escaped_url = output.escape(str(url)) if COMPATIBLE_OUTPUT else str(url)
        if COMPATIBLE_OUTPUT:
            print_status(f"Error encoding URL {escaped_url}: {e}", "warning")
        else:
            print(f"Error encoding URL {escaped_url}: {e}")
        return None

def safe_virustotal_request(url, headers, original_url):
    """Safely make VirusTotal request with retry logic."""
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            return response
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES - 1:
                escaped_url = output.escape(str(original_url)) if COMPATIBLE_OUTPUT else str(original_url)
                if COMPATIBLE_OUTPUT:
                    print_status(f"Timeout for {escaped_url}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})", "warning")
                else:
                    print(f"Timeout for {escaped_url}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(2)
            else:
                escaped_url = output.escape(str(original_url)) if COMPATIBLE_OUTPUT else str(original_url)
                if COMPATIBLE_OUTPUT:
                    print_status(f"Final timeout for {escaped_url} after {MAX_RETRIES} attempts", "warning")
                else:
                    print(f"Final timeout for {escaped_url} after {MAX_RETRIES} attempts")
                return None
        except requests.exceptions.ConnectionError:
            if attempt < MAX_RETRIES - 1:
                escaped_url = output.escape(str(original_url)) if COMPATIBLE_OUTPUT else str(original_url)
                if COMPATIBLE_OUTPUT:
                    print_status(f"Connection error for {escaped_url}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})", "warning")
                else:
                    print(f"Connection error for {escaped_url}, retrying... (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(2)
            else:
                escaped_url = output.escape(str(original_url)) if COMPATIBLE_OUTPUT else str(original_url)
                if COMPATIBLE_OUTPUT:
                    print_status(f"Final connection error for {escaped_url} after {MAX_RETRIES} attempts", "warning")
                else:
                    print(f"Final connection error for {escaped_url} after {MAX_RETRIES} attempts")
                return None
        except Exception as e:
            escaped_url = output.escape(str(original_url)) if COMPATIBLE_OUTPUT else str(original_url)
            if COMPATIBLE_OUTPUT:
                print_status(f"Unexpected error querying {escaped_url}: {e}", "error")
            else:
                print(f"Unexpected error querying {escaped_url}: {e}")
            return None
    
    return None

def safe_handle_rate_limit(url):  # Also fix in url_extractor.py
    """Safely handle VirusTotal rate limiting with user choice."""
    try:
        while True:
            try:
                choice = input(
                    "VirusTotal API rate limit reached.\n"
                    "Type 'wait' to wait 60 seconds, or 'skip' (or press Enter) to proceed without checking: "
                ).strip().lower()
                
                if choice == "wait":
                    print("Waiting 60 seconds...")
                    time.sleep(60)
                    return "wait"
                elif choice == "skip" or choice == "":  # FIXED: Accept empty input as skip
                    return "skip"
                else:
                    print("Invalid input. Please type 'wait', 'skip', or press Enter.")
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
                    comment = (f"{malicious} vendor flagged this domain as malicious"
                               if malicious == 1 else
                               f"{malicious} vendors flagged this domain as malicious")
                    cache[url] = ("malicious", comment)
                elif suspicious > 0:
                    comment = (f"{suspicious} vendor flagged this domain as suspicious"
                               if suspicious == 1 else
                               f"{suspicious} vendors flagged this domain as suspicious")
                    cache[url] = ("suspicious", comment)
                elif harmless > 0:
                    comment = (f"{harmless} vendor reported this domain as benign"
                               if harmless == 1 else
                               f"{harmless} vendors reported this domain as benign")
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
        escaped_url = output.escape(str(url)) if COMPATIBLE_OUTPUT else str(url)
        if COMPATIBLE_OUTPUT:
            print_status(f"Error querying VirusTotal for URL {escaped_url}: {e}", "error")
        else:
            print(f"Error querying VirusTotal for URL {escaped_url}: {e}")
        cache[url] = ("unchecked", "Unexpected error during check")

    return cache[url]

def safe_get_user_input(prompt):
    """Safely get user input with error handling."""
    try:
        response = input(prompt).strip().lower()
        return response
    except (KeyboardInterrupt, EOFError):
        print("\nSkipping...")
        return "n"
    except Exception:
        return "n"

def analyze_urls(msg_obj, api_key):
    """Analyze URLs from both email headers AND body content with domain-based grouping."""
    try:
        # Import the global variable from main module
        try:
            import sys
            main_module = sys.modules.get('__main__') or sys.modules.get('phishalyzer')
            if main_module:
                global_results = main_module
            else:
                global_results = None
        except Exception:
            global_results = None
        
        # CHANGED: Use the new complete URL extraction function
        url_list = safe_extract_urls_from_email_complete(msg_obj)
        
        if not url_list:
            if COMPATIBLE_OUTPUT:
                print_status("URL analysis completed successfully.", "success")
                output.print("[green]No URLs were detected in the email body or headers.[/green]")
                output.print("This could indicate:")
                output.print("- Clean email with no external links")
                output.print("- URLs may be obfuscated or embedded within attachments")
                output.print("- Manual verification may still be needed")
            else:
                print("URL analysis completed successfully.")
                print("No URLs were detected in the email body or headers.")
                print("This could indicate:")
                print("- Clean email with no external links")
                print("- URLs may be obfuscated or embedded within attachments")
                print("- Manual verification may still be needed")
            
            if global_results:
                try:
                    setattr(global_results, 'last_url_analysis_results', None)
                except Exception:
                    pass
            return []
        
        # Group URLs by domain
        domain_groups = defaultdict(list)
        for url in url_list:
            domain = extract_domain(url)
            domain_groups[domain].append(url)
        
        cache = {}
        results = []

        # Analyze each domain
        for domain, urls in domain_groups.items():
            try:
                # Get representative URL (shortest one)
                representative_url = get_shortest_url_for_domain(urls)
                
                # Check VirusTotal for the representative URL
                verdict, comment = check_url_virustotal(representative_url, api_key, cache)
                
                results.append({
                    'domain': domain,
                    'urls': urls,
                    'representative_url': representative_url,
                    'verdict': verdict,
                    'comment': comment,
                    'url_count': len(urls)
                })
                
            except Exception as e:
                escaped_domain = output.escape(str(domain)) if COMPATIBLE_OUTPUT else str(domain)
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error processing domain {escaped_domain}: {e}", "error")
                else:
                    print(f"Error processing domain {escaped_domain}: {e}")
                results.append({
                    'domain': domain,
                    'urls': urls,
                    'representative_url': urls[0] if urls else "",
                    'verdict': "unchecked",
                    'comment': f"Processing error: {e}",
                    'url_count': len(urls)
                })

        # Sort results by verdict priority
        try:
            sort_order = {"malicious": 0, "suspicious": 1, "unchecked": 2, "benign": 3}
            results.sort(key=lambda x: (sort_order.get(x['verdict'], 4), x['domain']))
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Warning: Could not sort results: {e}", "warning")
            else:
                print(f"Warning: Could not sort results: {e}")

        # Store results globally for later viewing
        if global_results:
            try:
                setattr(global_results, 'last_url_analysis_results', results)
            except Exception:
                pass

        # Display results with universal output system
        try:
            # Group results by verdict
            malicious_domains = [r for r in results if r['verdict'] == 'malicious']
            suspicious_domains = [r for r in results if r['verdict'] == 'suspicious']
            benign_domains = [r for r in results if r['verdict'] == 'benign']
            unchecked_domains = [r for r in results if r['verdict'] == 'unchecked']
            
            total_urls = sum(r['url_count'] for r in results)
            total_domains = len(results)
            
            # Use universal output for everything
            if COMPATIBLE_OUTPUT:
                output.print(f"Found [blue]{total_urls}[/blue] URL{'s' if total_urls != 1 else ''} across [blue]{total_domains}[/blue] domain{'s' if total_domains != 1 else ''}")
            else:
                print(f"Found {total_urls} URL{'s' if total_urls != 1 else ''} across {total_domains} domain{'s' if total_domains != 1 else ''}")
            
            # Display MALICIOUS domains (first)
            if malicious_domains:
                malicious_count = len(malicious_domains)
                
                print()  # Space before section
                if COMPATIBLE_OUTPUT:
                    output.print(f"[red]MALICIOUS DOMAINS ({malicious_count}):[/red]")
                else:
                    print(f"MALICIOUS DOMAINS ({malicious_count}):")
                    
                for result in malicious_domains:
                    domain = result['domain']
                    url_count = result['url_count']
                    comment = result['comment']
                    representative_url = result['representative_url']
                    
                    # Apply working defanging and escaping
                    display_domain = simple_defang(domain)
                    escaped_domain = output.escape(display_domain) if COMPATIBLE_OUTPUT else display_domain
                    escaped_comment = output.escape(comment) if COMPATIBLE_OUTPUT else comment
                    
                    print(f"- {escaped_domain} ({url_count} URL{'s' if url_count != 1 else ''}) - {escaped_comment}")
                    
                    if representative_url:
                        display_url = simple_defang(representative_url)
                        escaped_url = output.escape(display_url) if COMPATIBLE_OUTPUT else display_url
                        print(f"  Sample: {escaped_url}")
            
            # Display SUSPICIOUS domains
            if suspicious_domains:
                suspicious_count = len(suspicious_domains)
                
                print()  # Space before section
                if COMPATIBLE_OUTPUT:
                    output.print(f"[orange3]SUSPICIOUS DOMAINS ({suspicious_count}):[/orange3]")
                else:
                    print(f"SUSPICIOUS DOMAINS ({suspicious_count}):")
                    
                for result in suspicious_domains:
                    domain = result['domain']
                    url_count = result['url_count']
                    comment = result['comment']
                    representative_url = result['representative_url']
                    
                    # Apply working defanging and escaping
                    display_domain = simple_defang(domain)
                    escaped_domain = output.escape(display_domain) if COMPATIBLE_OUTPUT else display_domain
                    escaped_comment = output.escape(comment) if COMPATIBLE_OUTPUT else comment
                    
                    print(f"- {escaped_domain} ({url_count} URL{'s' if url_count != 1 else ''}) - {escaped_comment}")
                    
                    if representative_url:
                        display_url = simple_defang(representative_url)
                        escaped_url = output.escape(display_url) if COMPATIBLE_OUTPUT else display_url
                        print(f"  Sample: {escaped_url}")
            
            # Display UNCHECKED domains
            if unchecked_domains:
                unchecked_count = len(unchecked_domains)
                
                print()  # Space before section
                if COMPATIBLE_OUTPUT:
                    output.print(f"[orange3]UNCHECKED DOMAINS ({unchecked_count}):[/orange3]")
                else:
                    print(f"UNCHECKED DOMAINS ({unchecked_count}):")
                
                # Group malformed/truncated URLs together
                malformed_domains = [r for r in unchecked_domains if r['domain'] in ['malformed-urls', 'truncated-urls', 'unknown']]
                normal_unchecked = [r for r in unchecked_domains if r['domain'] not in ['malformed-urls', 'truncated-urls', 'unknown']]
                
                # Show normal unchecked domains first
                if normal_unchecked and len(normal_unchecked) <= 3:
                    for result in normal_unchecked:
                        domain = result['domain']
                        url_count = result['url_count']
                        comment = result['comment']
                        
                        # Apply working defanging and escaping
                        display_domain = simple_defang(domain)
                        escaped_domain = output.escape(display_domain) if COMPATIBLE_OUTPUT else display_domain
                        escaped_comment = output.escape(comment) if COMPATIBLE_OUTPUT else comment
                        
                        print(f"- {escaped_domain} ({url_count} URL{'s' if url_count != 1 else ''}) - {escaped_comment}")
                
                # Group malformed URLs together
                if malformed_domains:
                    malformed_count = len(malformed_domains)
                    malformed_url_count = sum(r['url_count'] for r in malformed_domains)
                    
                    if normal_unchecked and len(normal_unchecked) > 3:
                        # Show condensed view for all unchecked
                        total_unchecked_urls = sum(r['url_count'] for r in unchecked_domains)
                        print(f"- {unchecked_count} domains with {total_unchecked_urls} URL{'s' if total_unchecked_urls != 1 else ''} total - Not found in VirusTotal")
                    else:
                        # Show malformed separately
                        print(f"- {malformed_count} malformed/truncated domains ({malformed_url_count} URL{'s' if malformed_url_count != 1 else ''}) - Not found in VirusTotal")
                    
                    # Show samples from normal domains first, then malformed if needed
                    sample_urls = []
                    sample_count = min(3, len(normal_unchecked))
                    
                    for i in range(sample_count):
                        url = normal_unchecked[i]['representative_url']
                        if url:
                            display_url = simple_defang(url)
                            escaped_url = output.escape(display_url) if COMPATIBLE_OUTPUT else display_url
                            sample_urls.append(escaped_url)
                    
                    # If we need more samples and have malformed URLs
                    if len(sample_urls) < 3 and malformed_domains:
                        remaining_samples = 3 - len(sample_urls)
                        for i in range(min(remaining_samples, len(malformed_domains))):
                            url = malformed_domains[i]['representative_url']
                            if url:
                                display_url = simple_defang(url)
                                escaped_url = output.escape(display_url) if COMPATIBLE_OUTPUT else display_url
                                sample_urls.append(escaped_url)
                    
                    if sample_urls:
                        print(f"  Samples: {', '.join(sample_urls)}")
                        remaining_domains = unchecked_count - len(sample_urls)
                        if remaining_domains > 0:
                            print(f"  ... and {remaining_domains} more")
                
                elif len(normal_unchecked) > 3:
                    # Only normal unchecked domains, too many to show individually
                    total_unchecked_urls = sum(r['url_count'] for r in unchecked_domains)
                    print(f"- {unchecked_count} domains with {total_unchecked_urls} URL{'s' if total_unchecked_urls != 1 else ''} total - Not found in VirusTotal")
                    
                    # Show first few samples
                    sample_urls = []
                    sample_count = min(3, len(normal_unchecked))
                    for i in range(sample_count):
                        url = normal_unchecked[i]['representative_url']
                        if url:
                            display_url = simple_defang(url)
                            escaped_url = output.escape(display_url) if COMPATIBLE_OUTPUT else display_url
                            sample_urls.append(escaped_url)
                    
                    if sample_urls:
                        print(f"  Samples: {', '.join(sample_urls)}")
                        if unchecked_count > sample_count:
                            print(f"  ... and {unchecked_count - sample_count} more")
            
            # Display BENIGN domains (last)
            if benign_domains:
                benign_count = len(benign_domains)
                
                print()  # Space before section
                if COMPATIBLE_OUTPUT:
                    output.print(f"[green]BENIGN DOMAINS ({benign_count}):[/green]")
                else:
                    print(f"BENIGN DOMAINS ({benign_count}):")
                    
                for result in benign_domains:
                    domain = result['domain']
                    url_count = result['url_count']
                    comment = result['comment']
                    
                    # Apply working defanging and escaping
                    display_domain = simple_defang(domain)
                    escaped_domain = output.escape(display_domain) if COMPATIBLE_OUTPUT else display_domain
                    escaped_comment = output.escape(comment) if COMPATIBLE_OUTPUT else comment
                    
                    print(f"- {escaped_domain} ({url_count} URL{'s' if url_count != 1 else ''}) - {escaped_comment}")
            
            # Show menu hint if there are domains with multiple URLs or many domains
            domains_with_multiple = [r for r in results if r['url_count'] > 1]
            if domains_with_multiple or total_domains > 5:
                print()  # Space before menu hint
                if COMPATIBLE_OUTPUT:
                    output.print("[blue][Use menu option 'View collapsed URL variations' for full breakdown][/blue]")
                else:
                    print("[Use menu option 'View collapsed URL variations' for full breakdown]")
                    
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error displaying URL analysis results: {e}", "error")
            else:
                print(f"Error displaying URL analysis results: {e}")

        return results

    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Critical error in URL analysis: {e}", "error")
            print_status("URL analysis could not be completed.", "warning")
        else:
            print(f"Critical error in URL analysis: {e}")
            print("URL analysis could not be completed.")
        return []