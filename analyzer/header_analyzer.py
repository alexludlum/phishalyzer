import re
from email.message import Message

# Import universal output system
try:
    from .compatible_output import output, print_status
    COMPATIBLE_OUTPUT = True
except ImportError:
    COMPATIBLE_OUTPUT = False

from . import defanger

# IMPROVED IP patterns - much more precise to avoid timestamp conflicts
IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DEFANGED_IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b')

# IMPROVED IPv6 patterns - ordered by specificity
IPV6_LOOPBACK_PATTERN = re.compile(r'\b::1\b')  # Most specific: IPv6 loopback
IPV6_COMPRESSED_PATTERN = re.compile(r'\b[0-9a-fA-F]+::[0-9a-fA-F:]*\b')  # Has compression (::)
IPV6_FULL_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b')  # Full format
DEFANGED_IPV6_PATTERN = re.compile(r'\b[0-9a-fA-F]{1,4}(?:\[:\][0-9a-fA-F]{0,4}){2,7}\b')  # Defanged
DEFANGED_IPV6_COMPRESSED = re.compile(r'\b[0-9a-fA-F]*\[::\][0-9a-fA-F:]*\b')  # Defanged with compression

# Precise timestamp pattern (unchanged - works well)
FULL_TIMESTAMP_PATTERN = re.compile(
    r'\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s*(?:[-+]\d{4})?\b'
)

# Authentication result terms
FAILURE_TERMS = {
    "fail", "softfail", "temperror", "permerror", "invalid",
    "missing", "bad", "hardfail", "not", "signed"
}
PASS_TERMS = {
    "pass", "bestguesspass"
}
WARNING_TERMS = {
    "neutral", "policy", "none", "unknown"
}

def safe_get_header(headers, key, default=""):
    """Safely get header value with error handling."""
    try:
        value = headers.get(key, default)
        if value is None:
            return default
        return str(value) if value else default
    except Exception:
        return default

def safe_regex_search(pattern, text, default=None):
    """Safely perform regex search with error handling."""
    try:
        if not text or not isinstance(text, str):
            return default
        match = pattern.search(text)
        return match if match else default
    except Exception:
        return default

def apply_defanging_if_enabled(text):
    """Apply defanging to text if defang mode is enabled"""
    try:
        if defanger.should_defang():
            return defanger.defang_text(str(text))
        else:
            return str(text)
    except Exception:
        return str(text)

def smart_highlight_text(text, content_type="basic"):
    """
    FIXED smart highlighting with improved IPv6 patterns that actually work.
    Order: Defang → Color auth terms → Highlight IPs (improved) → Highlight timestamps
    """
    try:
        if not isinstance(text, str):
            text = str(text)
        
        # Step 1: Apply defanging first
        processed_text = apply_defanging_if_enabled(text)
        
        # Step 2: Handle authentication result coloring (word-by-word)
        if content_type == "authentication":
            # Split into words and process each one
            words = processed_text.split()
            colored_words = []
            
            for word in words:
                # Extract the core term (remove punctuation for matching)
                core_term = re.sub(r'[^\w-]', '', word.lower())
                
                # Color based on term type
                if core_term in FAILURE_TERMS or "not signed" in word.lower():
                    colored_words.append(f"[red]{word}[/red]")
                elif core_term in PASS_TERMS:
                    colored_words.append(f"[green]{word}[/green]")
                elif core_term in WARNING_TERMS:
                    colored_words.append(f"[orange3]{word}[/orange3]")
                else:
                    colored_words.append(word)
            
            processed_text = " ".join(colored_words)
        
        # Step 3: Highlight ALL IP addresses with IMPROVED patterns (skip for received hops)
        if content_type != "received":
            def make_ip_yellow(match):
                ip_text = match.group(0)
                # Avoid double-coloring already processed authentication terms
                if '[red]' not in ip_text and '[green]' not in ip_text and '[orange3]' not in ip_text and '\033[' not in ip_text:
                    return f"[yellow]{ip_text}[/yellow]"
                return ip_text
            
            # IPv4 (regular and defanged) - unchanged, these work fine
            processed_text = re.sub(IPV4_PATTERN, make_ip_yellow, processed_text)
            processed_text = re.sub(DEFANGED_IPV4_PATTERN, make_ip_yellow, processed_text)
            
            # IMPROVED IPv6 patterns - applied in order of specificity
            
            # 1. IPv6 loopback (::1) - most specific first
            processed_text = re.sub(IPV6_LOOPBACK_PATTERN, make_ip_yellow, processed_text)
            
            # 2. IPv6 with compression (contains ::) - but not just ::1
            processed_text = re.sub(IPV6_COMPRESSED_PATTERN, make_ip_yellow, processed_text)
            
            # 3. Full IPv6 (no compression) - more flexible length matching
            processed_text = re.sub(IPV6_FULL_PATTERN, make_ip_yellow, processed_text)
            
            # 4. Defanged IPv6 (simple format)
            processed_text = re.sub(DEFANGED_IPV6_PATTERN, make_ip_yellow, processed_text)
            
            # 5. Defanged IPv6 with compression
            processed_text = re.sub(DEFANGED_IPV6_COMPRESSED, make_ip_yellow, processed_text)
        
        # Step 4: Highlight timestamps (skip for received hops)
        if content_type == "received_skip_highlighting":  # Changed condition to never match
            def make_timestamp_blue(match):
                timestamp_text = match.group(0)
                # Prevent double-coloring - avoid areas already processed
                if '[blue]' not in timestamp_text and '[yellow]' not in timestamp_text and '\033[' not in timestamp_text:
                    return f"[blue]{timestamp_text}[/blue]"
                return timestamp_text
            
            processed_text = re.sub(FULL_TIMESTAMP_PATTERN, make_timestamp_blue, processed_text)
            
            # Also highlight timezone markers like (UTC), (PDT)
            timezone_pattern = re.compile(r'\([A-Z]{2,4}\)')
            processed_text = re.sub(timezone_pattern, make_timestamp_blue, processed_text)
        
        return processed_text
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Warning: Error in smart highlighting: {e}", "warning")
        return str(text)

def analyze_headers(msg_obj: Message):
    """Analyze email headers with proper highlighting that actually works."""
    
    try:
        if not msg_obj:
            if COMPATIBLE_OUTPUT:
                print_status("Error: No email message object provided", "error")
            else:
                print("Error: No email message object provided")
            return
        
        # Safely extract headers
        try:
            headers = dict(msg_obj.items()) if hasattr(msg_obj, 'items') else {}
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error extracting headers: {e}", "error")
                print_status("Attempting basic header analysis...", "warning")
            else:
                print(f"Error extracting headers: {e}")
                print("Attempting basic header analysis...")
            headers = {}

        # Display basic headers
        try:
            basics = ["From", "Return-Path", "Reply-To", "Message-ID", "Subject", "Date"]
            for key in basics:
                try:
                    val = safe_get_header(headers, key)
                    if not val or (isinstance(val, str) and not val.strip()):
                        if COMPATIBLE_OUTPUT:
                            output.print(f"[blue]{key}:[/blue] [red]MISSING[/red]")
                        else:
                            print(f"{key}: MISSING")
                    else:
                        # Apply smart highlighting (mainly for IPs in these headers)
                        highlighted_val = smart_highlight_text(val, "basic")
                        if COMPATIBLE_OUTPUT:
                            output.print(f"[blue]{key}:[/blue] {highlighted_val}")
                        else:
                            # Strip all markup for non-compatible terminals
                            clean_val = re.sub(r'\[/?[^\]]*\]', '', highlighted_val)
                            print(f"{key}: {clean_val}")
                except Exception as e:
                    if COMPATIBLE_OUTPUT:
                        output.print(f"[blue]{key}:[/blue] [red]ERROR: {e}[/red]")
                    else:
                        print(f"{key}: ERROR: {e}")
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error displaying basic headers: {e}", "error")
            else:
                print(f"Error displaying basic headers: {e}")

        if COMPATIBLE_OUTPUT:
            output.print("")  # Blank line
        else:
            print()

        # Display authentication results with WORKING term coloring
        try:
            auth_results_val = safe_get_header(headers, "Authentication-Results")
            if auth_results_val:
                # Apply defanging first
                defanged_auth = apply_defanging_if_enabled(auth_results_val)
                
                # MANUALLY apply the highlighting in safe order
                highlighted_auth = defanged_auth
                
                # STEP 1: Color authentication terms first
                for term in FAILURE_TERMS:
                    # Use word boundaries and case-insensitive matching
                    pattern = rf'\b{re.escape(term)}\b'
                    highlighted_auth = re.sub(pattern, f'[red]{term}[/red]', highlighted_auth, flags=re.IGNORECASE)
                
                for term in PASS_TERMS:
                    pattern = rf'\b{re.escape(term)}\b'
                    highlighted_auth = re.sub(pattern, f'[green]{term}[/green]', highlighted_auth, flags=re.IGNORECASE)
                
                for term in WARNING_TERMS:
                    pattern = rf'\b{re.escape(term)}\b'
                    highlighted_auth = re.sub(pattern, f'[orange3]{term}[/orange3]', highlighted_auth, flags=re.IGNORECASE)
                
                # Handle special multi-word cases
                highlighted_auth = re.sub(r'\bnot\s+signed\b', '[red]not signed[/red]', highlighted_auth, flags=re.IGNORECASE)
                
                # STEP 2: Highlight IP addresses (avoiding already-colored areas)
                def safe_ip_highlight_auth(match):
                    ip_text = match.group(0)
                    # Only highlight if not already in colored text
                    if '[red]' not in ip_text and '[green]' not in ip_text and '[orange3]' not in ip_text and '\033[' not in ip_text:
                        return f'[yellow]{ip_text}[/yellow]'
                    return ip_text
                
                # Apply all IP patterns
                highlighted_auth = re.sub(IPV4_PATTERN, safe_ip_highlight_auth, highlighted_auth)
                highlighted_auth = re.sub(DEFANGED_IPV4_PATTERN, safe_ip_highlight_auth, highlighted_auth)
                highlighted_auth = re.sub(IPV6_LOOPBACK_PATTERN, safe_ip_highlight_auth, highlighted_auth)
                highlighted_auth = re.sub(IPV6_COMPRESSED_PATTERN, safe_ip_highlight_auth, highlighted_auth)
                highlighted_auth = re.sub(IPV6_FULL_PATTERN, safe_ip_highlight_auth, highlighted_auth)
                highlighted_auth = re.sub(DEFANGED_IPV6_PATTERN, safe_ip_highlight_auth, highlighted_auth)
                highlighted_auth = re.sub(DEFANGED_IPV6_COMPRESSED, safe_ip_highlight_auth, highlighted_auth)
                
                if COMPATIBLE_OUTPUT:
                    output.print(f"[blue]Authentication-Results:[/blue] {highlighted_auth}")
                else:
                    clean_auth = re.sub(r'\[/?[^\]]*\]', '', highlighted_auth)
                    print(f"Authentication-Results: {clean_auth}")
            else:
                if COMPATIBLE_OUTPUT:
                    output.print(f"[blue]Authentication-Results:[/blue] [red]MISSING[/red]")
                else:
                    print("Authentication-Results: MISSING")
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                output.print(f"[blue]Authentication-Results:[/blue] [red]ERROR: {e}[/red]")
            else:
                print(f"Authentication-Results: ERROR: {e}")

        if COMPATIBLE_OUTPUT:
            output.print("")  # Blank line
        else:
            print()

        # Store Received hops but don't display them - show summary instead
        try:
            # Store hops globally for later viewing
            try:
                import sys
                main_module = sys.modules.get('__main__') or sys.modules.get('phishalyzer')
                if main_module:
                    global_results = main_module
                else:
                    global_results = None
            except Exception:
                global_results = None

            hops = []
            try:
                hop_headers = msg_obj.get_all("Received", []) if hasattr(msg_obj, 'get_all') else []
                if hop_headers:
                    for i, hop in enumerate(hop_headers, 1):
                        try:
                            # Apply only defanging, NO color highlighting
                            defanged_hop = apply_defanging_if_enabled(str(hop))
                            hops.append({
                                'index': i,
                                'content': defanged_hop,
                                'raw': str(hop)
                            })
                        except Exception as e:
                            hops.append({
                                'index': i,
                                'content': f"Error processing hop: {e}",
                                'raw': f"Error: {e}"
                            })
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error extracting Received headers: {e}", "error")
                else:
                    print(f"Error extracting Received headers: {e}")

            # Store hops globally
            if global_results:
                try:
                    setattr(global_results, 'last_received_hops', hops)
                except Exception:
                    pass

            # Display summary instead of full hops
            if hops:
                if COMPATIBLE_OUTPUT:
                    output.print(f"[blue]Received Hops:[/blue] {len(hops)} hop{'s' if len(hops) != 1 else ''} found")
                    output.print("[blue][Use menu option 'View email routing hops' for full details][/blue]")
                else:
                    print(f"Received Hops: {len(hops)} hop{'s' if len(hops) != 1 else ''} found")
                    print("[Use menu option 'View email routing hops' for full details]")
            else:
                if COMPATIBLE_OUTPUT:
                    output.print("[blue]Received Hops:[/blue] No Received headers found")
                else:
                    print("Received Hops: No Received headers found")

        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error in Received hops analysis: {e}", "error")
            else:
                print(f"Error in Received hops analysis: {e}")

        if COMPATIBLE_OUTPUT:
            output.print("")  # Blank line
        else:
            print()

        # Security assessment
        try:
            factors_benign = []
            factors_warn = []
            factors_malicious = []

            def get_auth_result(mech: str):
                try:
                    auth_res = safe_get_header(headers, "Authentication-Results", "").lower()
                    # Look for mech=result pattern
                    pattern = re.compile(rf"\b{mech}=([a-z]+)")
                    m = safe_regex_search(pattern, auth_res)
                    if m:
                        return m.group(1)
                    else:
                        return "missing"
                except Exception:
                    return "missing"

            # Check SPF, DKIM, DMARC
            for mech in ["spf", "dkim", "dmarc"]:
                try:
                    result = get_auth_result(mech)
                    
                    if result in FAILURE_TERMS or result == "missing":
                        factors_malicious.append(f"{mech.upper()}: {result}")
                    elif result in WARNING_TERMS:
                        factors_warn.append(f"{mech.upper()}: {result}")
                    elif result in PASS_TERMS:
                        factors_benign.append(f"{mech.upper()}: {result}")
                    else:
                        factors_warn.append(f"{mech.upper()}: {result}")
                except Exception as e:
                    factors_warn.append(f"{mech.upper()}: Error - {e}")

            # Check Reply-To presence
            try:
                reply_to = safe_get_header(headers, "Reply-To")
                if not reply_to or not reply_to.strip():
                    factors_warn.append("Reply-To header missing")
                else:
                    factors_benign.append("Reply-To header present")
            except Exception:
                factors_warn.append("Reply-To header check failed")

            # Check From vs Return-Path domains
            try:
                from_addr = safe_get_header(headers, "From", "").lower()
                return_path = safe_get_header(headers, "Return-Path", "").lower()
                
                # Extract domains
                from_domain = ""
                return_domain = ""
                
                if "@" in from_addr:
                    from_domain = from_addr.split("@")[-1].strip("<>").replace('[.]', '.')
                if "@" in return_path:
                    return_domain = return_path.split("@")[-1].strip("<>")
                elif return_path:
                    return_domain = return_path.strip("<>")
                
                if from_domain and return_domain and return_domain not in from_domain:
                    factors_warn.append("Return-Path domain differs from From domain (possible spoofing)")
                elif from_domain and return_domain:
                    factors_benign.append("From and Return-Path domains match")
            except Exception:
                factors_warn.append("From/Return-Path comparison failed")

            # Display factors with proper section headers
            if factors_malicious:
                if COMPATIBLE_OUTPUT:
                    output.print("[red]Malicious factors:[/red]")
                else:
                    print("Malicious factors:")
                for f in factors_malicious:
                    escaped_f = output.escape(f) if COMPATIBLE_OUTPUT else f
                    print(f"  • {escaped_f}")

            if factors_warn:
                if COMPATIBLE_OUTPUT:
                    output.print("[orange3]Warning factors:[/orange3]")
                else:
                    print("Warning factors:")
                for f in factors_warn:
                    escaped_f = output.escape(f) if COMPATIBLE_OUTPUT else f
                    print(f"  • {escaped_f}")

            if factors_benign:
                if COMPATIBLE_OUTPUT:
                    output.print("[green]Benign factors:[/green]")
                else:
                    print("Benign factors:")
                for f in factors_benign:
                    escaped_f = output.escape(f) if COMPATIBLE_OUTPUT else f
                    print(f"  • {escaped_f}")

            if not (factors_benign or factors_warn or factors_malicious):
                print("  No security factors detected.")

            # Generate final verdict
            if factors_malicious:
                verdict_text = "HIGH RISK: Multiple security failures detected"
                verdict_color = "red"
            elif factors_warn and not factors_benign:
                verdict_text = "MEDIUM RISK: Warning signs detected"  
                verdict_color = "orange3"
            elif factors_warn and factors_benign:
                verdict_text = "LOW-MEDIUM RISK: Mixed indicators"
                verdict_color = "yellow"
            elif factors_benign and not factors_warn:
                verdict_text = "LOW RISK: Headers appear legitimate"
                verdict_color = "green"
            else:
                verdict_text = "UNKNOWN RISK: Insufficient data"
                verdict_color = "orange3"

            if COMPATIBLE_OUTPUT:
                output.print("")  # Blank line
                output.print(f"[blue bold]HEADER ASSESSMENT:[/blue bold] [{verdict_color}]{verdict_text}[/{verdict_color}]")
            else:
                print()
                print(f"HEADER ASSESSMENT: {verdict_text}")
            
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error in security assessment: {e}", "error")
            else:
                print(f"Error in security assessment: {e}")

    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Critical error in header analysis: {e}", "error")
            print_status("Header analysis could not be completed.", "warning")
        else:
            print(f"Critical error in header analysis: {e}")
            print("Header analysis could not be completed.")