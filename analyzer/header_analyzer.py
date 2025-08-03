import re
from email.message import Message

# Import compatible output system
try:
    from .compatible_output import output, print_status, create_colored_text
    COMPATIBLE_OUTPUT = True
except ImportError:
    # Fallback to regular print if compatible_output not available
    COMPATIBLE_OUTPUT = False
    print = print

from . import defanger

# Regex to match IPv4 addresses
IP_PATTERN = re.compile(
    r'\b('
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
    r')\b'
)

# Enhanced regex for timestamps in Received hops - multiple patterns
RECEIVED_DATE_PATTERNS = [
    # Full RFC-5322 style timestamps (Fri, 25 Jul 2025 17:03:12 -0700 (PDT))
    re.compile(
        r'\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+'
        r'\d{1,2}\s+'
        r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
        r'\d{4}\s+'
        r'\d{2}:\d{2}:\d{2}\s*'
        r'(?:[-+]\d{4})?'
        r'(?:\s*\([A-Z]{2,4}\))?'  # Timezone abbreviation in parentheses like (PDT)
    ),
    # ISO format (2025-07-25T17:03:12)
    re.compile(r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[-+]\d{2}:?\d{2})?\b'),
    # Simple date format (25 Jul 2025)
    re.compile(r'\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\b'),
    # Time with timezone (17:03:12 -0700)
    re.compile(r'\b\d{2}:\d{2}:\d{2}\s*[-+]\d{4}\b'),
    # Time with GMT/UTC (18:02:58 GMT)
    re.compile(r'\b\d{2}:\d{2}:\d{2}\s+(?:GMT|UTC)\b'),
    # Simple time format (17:03:12)
    re.compile(r'\b\d{2}:\d{2}:\d{2}\b'),
    # Timezone abbreviations in parentheses (PDT), (EST), etc.
    re.compile(r'\([A-Z]{2,4}\)'),
]

FAILURE_TERMS = {
    "fail", "softfail", "temperror", "permerror", "invalid",
    "missing", "bad", "hardfail", "not signed"
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
        # Handle cases where header value might not be a string
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

def safe_regex_finditer(pattern, text):
    """Safely perform regex finditer with error handling."""
    try:
        if not text or not isinstance(text, str):
            return []
        return list(pattern.finditer(text))
    except Exception:
        return []

def analyze_headers(msg_obj: Message):
    """Analyze email headers with comprehensive error handling."""
    
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

        def create_defanged_text(text_content, color_style=None):
            """Create a text object with defanged content if defanging is enabled."""
            try:
                if defanger.should_defang():
                    defanged_content = defanger.defang_text(str(text_content))
                    escaped_content = output.escape(defanged_content)
                    if COMPATIBLE_OUTPUT:
                        return create_colored_text(escaped_content, color_style or "white")
                    else:
                        return escaped_content
                else:
                    escaped_content = output.escape(str(text_content)) if COMPATIBLE_OUTPUT else str(text_content)
                    if COMPATIBLE_OUTPUT:
                        return create_colored_text(escaped_content, color_style or "white")
                    else:
                        return escaped_content
            except Exception:
                escaped_content = str(text_content)
                if COMPATIBLE_OUTPUT:
                    return create_colored_text(escaped_content, color_style or "white")
                else:
                    return escaped_content

        def color_key(key: str):
            try:
                if COMPATIBLE_OUTPUT:
                    return create_colored_text(str(key) + ":", "blue")
                else:
                    return f"{str(key)}:"
            except Exception:
                return "Unknown:"

        def highlight_ips_only(text: str):
            """Highlight only IP addresses, not timestamps (for basic headers)."""
            try:
                if not isinstance(text, str):
                    text = str(text)
                
                # Apply defanging if enabled
                if defanger.should_defang():
                    text = defanger.defang_text(text)
                
                # For non-Rich environments, just return escaped text
                escaped_text = output.escape(text) if COMPATIBLE_OUTPUT else text
                
                if COMPATIBLE_OUTPUT and output.use_rich:
                    # Use Rich Text object for highlighting
                    from rich.text import Text
                    t = Text(escaped_text)
                    
                    # Find IP addresses and highlight them
                    matches = safe_regex_finditer(IP_PATTERN, escaped_text)
                    for match in matches:
                        t.stylize("yellow", match.start(), match.end())
                    
                    return t
                else:
                    # Simple return for non-Rich environments
                    return escaped_text
                    
            except Exception:
                return str(text)

        def highlight_ips_and_dates_in_hops(text: str):
            """Highlight IPs and timestamps specifically for Received hops."""
            try:
                if not isinstance(text, str):
                    text = str(text)
                
                # Apply defanging if enabled
                if defanger.should_defang():
                    text = defanger.defang_text(text)
                
                escaped_text = output.escape(text) if COMPATIBLE_OUTPUT else text
                
                if COMPATIBLE_OUTPUT and output.use_rich:
                    # Use Rich Text object for highlighting
                    from rich.text import Text
                    t = Text(escaped_text)
                    
                    # Track all matches to avoid overlapping
                    matches = []
                    
                    # Find IP addresses
                    ip_matches = safe_regex_finditer(IP_PATTERN, escaped_text)
                    for match in ip_matches:
                        matches.append((match.start(), match.end(), "yellow"))
                    
                    # Find dates/timestamps
                    for pattern in RECEIVED_DATE_PATTERNS:
                        try:
                            date_matches = safe_regex_finditer(pattern, escaped_text)
                            for match in date_matches:
                                # Check if this overlaps with existing matches
                                overlaps = any(
                                    not (match.end() <= start or match.start() >= end)
                                    for start, end, _ in matches
                                )
                                if not overlaps:
                                    matches.append((match.start(), match.end(), "blue"))
                        except Exception:
                            continue
                    
                    # Sort matches by start position (reversed for proper application)
                    matches.sort(key=lambda x: x[0], reverse=True)
                    
                    # Apply styling
                    for start, end, color in matches:
                        try:
                            t.stylize(color, start, end)
                        except Exception:
                            continue
                    
                    return t
                else:
                    # Simple return for non-Rich environments
                    return escaped_text
                    
            except Exception:
                return str(text)

        def color_auth_word(word: str):
            try:
                escaped_word = output.escape(str(word)) if COMPATIBLE_OUTPUT else str(word)
                lw = str(word).lower()
                
                if COMPATIBLE_OUTPUT:
                    if lw in FAILURE_TERMS:
                        return create_colored_text(escaped_word.upper(), "red")
                    elif lw in PASS_TERMS:
                        return create_colored_text(escaped_word, "green")
                    elif lw in WARNING_TERMS:
                        return create_colored_text(escaped_word, "orange3")
                    else:
                        return create_colored_text(escaped_word, "white")
                else:
                    return escaped_word
                    
            except Exception:
                return str(word)

        def color_authentication_results(value: str):
            try:
                if not isinstance(value, str):
                    value = str(value)
                
                if COMPATIBLE_OUTPUT and output.use_rich:
                    # Use Rich for complex formatting
                    from rich.text import Text
                    
                    tokens = re.split(r'(\s+|;)', value)
                    colored_tokens = []
                    
                    for token in tokens:
                        try:
                            if '=' in token:
                                mech, sep, status = token.partition('=')
                                colored_tokens.append(Text(output.escape(mech + sep)))
                                colored_tokens.append(color_auth_word(status))
                            else:
                                colored_tokens.append(Text(output.escape(token)))
                        except Exception:
                            colored_tokens.append(Text(output.escape(str(token))))

                    result = Text()
                    for t in colored_tokens:
                        try:
                            result.append(t)
                        except Exception:
                            continue

                    # Apply IP highlighting
                    try:
                        plain = result.plain
                        ip_matches = safe_regex_finditer(IP_PATTERN, plain)
                        for match in ip_matches:
                            result.stylize("yellow", match.start(), match.end())
                    except Exception:
                        pass

                    return result
                else:
                    # Simple processing for non-Rich environments
                    # Just apply defanging and return
                    if defanger.should_defang():
                        value = defanger.defang_text(value)
                    return output.escape(value) if COMPATIBLE_OUTPUT else value
                    
            except Exception:
                return str(value)

        def color_value(key: str, val: str):
            try:
                if not isinstance(val, str):
                    val = str(val)
                
                if key == "Authentication-Results":
                    return color_authentication_results(val)
                else:
                    # Apply defanging if enabled
                    try:
                        display_text = defanger.defang_text(val) if defanger.should_defang() else val
                    except Exception:
                        display_text = val
                    
                    if COMPATIBLE_OUTPUT:
                        # For basic headers, only highlight IPs
                        t = highlight_ips_only(display_text)
                        lw = val.lower()
                        
                        try:
                            if any(term in lw for term in FAILURE_TERMS):
                                return create_colored_text(output.escape(display_text).upper(), "red")
                            elif any(term in lw for term in PASS_TERMS):
                                return create_colored_text(output.escape(display_text), "green")
                            elif any(term in lw for term in WARNING_TERMS):
                                return create_colored_text(output.escape(display_text), "orange3")
                        except Exception:
                            pass
                        
                        return t
                    else:
                        return display_text
                        
            except Exception:
                return str(val)

        # Display basic headers
        try:
            basics = ["From", "Return-Path", "Reply-To", "Message-ID", "Subject", "Date"]
            for key in basics:
                try:
                    val = safe_get_header(headers, key)
                    if not val or (isinstance(val, str) and not val.strip()):
                        if COMPATIBLE_OUTPUT:
                            output.print(f"{color_key(key)} [red]MISSING[/red]")
                        else:
                            print(f"{key}: MISSING")
                    else:
                        if COMPATIBLE_OUTPUT:
                            key_part = color_key(key)
                            value_part = color_value(key, val)
                            if output.use_rich and hasattr(key_part, 'append') and hasattr(value_part, 'plain'):
                                # Both are Rich Text objects
                                combined = create_colored_text("", "white")
                                combined.append(key_part)
                                combined.append(" ")
                                combined.append(value_part)
                                output.print(combined)
                            else:
                                # At least one is a string
                                output.print(f"{key_part} {value_part}")
                        else:
                            print(f"{key}: {val}")
                except Exception as e:
                    if COMPATIBLE_OUTPUT:
                        output.print(f"{color_key(key)} [red]ERROR: {e}[/red]")
                    else:
                        print(f"{key}: ERROR: {e}")
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error displaying basic headers: {e}", "error")
            else:
                print(f"Error displaying basic headers: {e}")

        print()

        # Display authentication results
        try:
            auth_results_val = safe_get_header(headers, "Authentication-Results")
            if auth_results_val:
                if COMPATIBLE_OUTPUT:
                    key_part = color_key("Authentication-Results")
                    value_part = color_value("Authentication-Results", auth_results_val)
                    if output.use_rich and hasattr(key_part, 'append') and hasattr(value_part, 'plain'):
                        combined = create_colored_text("", "white")
                        combined.append(key_part)
                        combined.append(" ")
                        combined.append(value_part)
                        output.print(combined)
                    else:
                        output.print(f"{key_part} {value_part}")
                else:
                    print(f"Authentication-Results: {auth_results_val}")
            else:
                if COMPATIBLE_OUTPUT:
                    output.print(f"{color_key('Authentication-Results')} [red]MISSING[/red]")
                else:
                    print("Authentication-Results: MISSING")
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                output.print(f"{color_key('Authentication-Results')} [red]ERROR: {e}[/red]")
            else:
                print(f"Authentication-Results: ERROR: {e}")

        print()

        # Display Received hops
        try:
            if COMPATIBLE_OUTPUT:
                output.print("[blue]Received Hops:[/blue]")
            else:
                print("Received Hops:")
                
            try:
                hops = msg_obj.get_all("Received", []) if hasattr(msg_obj, 'get_all') else []
                if not hops:
                    print("  No Received headers found")
                else:
                    for i, hop in enumerate(hops, 1):
                        try:
                            if COMPATIBLE_OUTPUT:
                                label = create_colored_text(f"[{i}]", "blue")
                                hop_text = highlight_ips_and_dates_in_hops(str(hop))
                                if output.use_rich and hasattr(label, 'append') and hasattr(hop_text, 'plain'):
                                    combined = create_colored_text("", "white")
                                    combined.append(label)
                                    combined.append(" ")
                                    combined.append(hop_text)
                                    output.print(combined)
                                else:
                                    output.print(f"{label} {hop_text}")
                            else:
                                print(f"[{i}] {hop}")
                        except Exception as e:
                            print(f"  [{i}] Error processing hop: {e}")
            except Exception as e:
                print(f"  Error extracting Received headers: {e}")
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error in Received hops analysis: {e}", "error")
            else:
                print(f"Error in Received hops analysis: {e}")

        print()

        # Security assessment
        try:
            concerns = []
            factors_benign = []
            factors_warn = []
            factors_malicious = []

            def get_auth_result(mech: str):
                try:
                    auth_res = safe_get_header(headers, "Authentication-Results", "").lower()
                    m = safe_regex_search(re.compile(rf"{mech}=([a-z]+)"), auth_res)
                    if m:
                        return m.group(1)
                    else:
                        return None
                except Exception:
                    return None

            # Check SPF, DKIM, DMARC
            for mech in ["spf", "dkim", "dmarc"]:
                try:
                    result = get_auth_result(mech)
                    if not result:
                        result = "missing"
                    
                    if result in FAILURE_TERMS:
                        concerns.append("red")
                        factors_malicious.append(f"{mech.upper()}: Failure or missing (value: {result})")
                    elif result in WARNING_TERMS:
                        concerns.append("orange")
                        factors_warn.append(f"{mech.upper()}: Warning or Suspect (value: {result})")
                    elif result in PASS_TERMS:
                        concerns.append("green")
                        factors_benign.append(f"{mech.upper()}: Passed (value: {result})")
                    else:
                        concerns.append("orange")
                        factors_warn.append(f"{mech.upper()}: Ambiguous or unknown result (value: {result})")
                except Exception as e:
                    factors_warn.append(f"{mech.upper()}: Error checking result - {e}")

            # Check Reply-To
            try:
                reply_to = safe_get_header(headers, "Reply-To")
                if not reply_to or not reply_to.strip():
                    factors_warn.append("Reply-To header missing")
                else:
                    factors_benign.append("Reply-To header present")
            except Exception:
                factors_warn.append("Reply-To header check failed")

            # Check From vs Return-Path
            try:
                from_addr = safe_get_header(headers, "From", "").lower()
                return_path = safe_get_header(headers, "Return-Path", "").lower()
                if from_addr and return_path and return_path not in from_addr:
                    factors_warn.append("Return-Path domain does not match the From domain (possible spoofing)")
            except Exception:
                factors_warn.append("From/Return-Path comparison failed")

            # Generate verdict
            try:
                if all(c == "green" for c in concerns) and not factors_warn and not factors_malicious:
                    verdict_text = "Security concern unlikely, but verify other factors."
                    verdict_color = "green"
                elif "red" in concerns or factors_malicious:
                    verdict_text = "Likely security concern. Proceed with caution."
                    verdict_color = "red"
                else:
                    verdict_text = "Possible security concern detected."
                    verdict_color = "orange3"
            except Exception:
                verdict_text = "Could not determine security assessment."
                verdict_color = "orange3"

            # Display factors
            if factors_benign:
                if COMPATIBLE_OUTPUT:
                    output.print("[green]Benign factors:[/green]")
                else:
                    print("Benign factors:")
                for f in factors_benign:
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

            if factors_malicious:
                if COMPATIBLE_OUTPUT:
                    output.print("[red]Malicious factors:[/red]")
                else:
                    print("Malicious factors:")
                for f in factors_malicious:
                    escaped_f = output.escape(f) if COMPATIBLE_OUTPUT else f
                    print(f"  • {escaped_f}")

            if not (factors_benign or factors_warn or factors_malicious):
                print("  None detected.")

            print()
            
            if COMPATIBLE_OUTPUT:
                output.print(f"[blue]HEADER ASSESSMENT:[/blue] [{verdict_color}]{verdict_text}[/{verdict_color}]")
            else:
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