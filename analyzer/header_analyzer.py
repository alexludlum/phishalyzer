import re
from email.message import Message
from rich import print
from rich.text import Text
from rich.markup import escape
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
            print(Text("Error: No email message object provided", style="red"))
            return
        
        # Safely extract headers
        try:
            headers = dict(msg_obj.items()) if hasattr(msg_obj, 'items') else {}
        except Exception as e:
            print(f"[red]Error extracting headers: {e}[/red]")
            print("[yellow]Attempting basic header analysis...[/yellow]")
            headers = {}

        def create_defanged_text(text_content, color_style=None):
            """Create a Text object with defanged content if defanging is enabled."""
            try:
                if defanger.should_defang():
                    defanged_content = defanger.defang_text(str(text_content))
                    escaped_content = escape(defanged_content)
                    return Text(escaped_content, style=color_style)
                else:
                    escaped_content = escape(str(text_content))
                    return Text(escaped_content, style=color_style)
            except Exception:
                escaped_content = escape(str(text_content))
                return Text(escaped_content, style=color_style)

        def color_key(key: str) -> Text:
            try:
                return Text(escape(str(key)) + ":", style="blue")
            except Exception:
                return Text("Unknown:", style="blue")

        def highlight_ips_only(text: str) -> Text:
            """Highlight only IP addresses, not timestamps (for basic headers)."""
            try:
                if not isinstance(text, str):
                    text = str(text)
                
                # Apply defanging if enabled
                if defanger.should_defang():
                    text = defanger.defang_text(text)
                
                # Escape the text to prevent Rich markup interpretation
                escaped_text = escape(text)
                t = Text(escaped_text)
                
                # Find IP addresses in the original (non-escaped) text for highlighting
                matches = safe_regex_finditer(IP_PATTERN, text)
                # Since we've escaped the text, we need to find the positions in the escaped version
                # For simplicity, we'll highlight based on the escaped text pattern
                escaped_matches = safe_regex_finditer(IP_PATTERN, escaped_text)
                for match in escaped_matches:
                    t.stylize("yellow", match.start(), match.end())
                
                return t
            except Exception:
                return Text(escape(str(text)))

        def highlight_ips_and_dates_in_hops(text: str) -> Text:
            """Highlight IPs and timestamps specifically for Received hops."""
            try:
                if not isinstance(text, str):
                    text = str(text)
                
                # Apply defanging if enabled
                if defanger.should_defang():
                    text = defanger.defang_text(text)
                
                # Escape the text to prevent Rich markup interpretation
                escaped_text = escape(text)
                t = Text(escaped_text)
                
                # Track all matches to avoid overlapping
                matches = []
                
                # Find IP addresses in escaped text
                ip_matches = safe_regex_finditer(IP_PATTERN, escaped_text)
                for match in ip_matches:
                    matches.append((match.start(), match.end(), "yellow"))
                
                # Find dates/timestamps using patterns designed for Received hops
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
            except Exception:
                return Text(escape(str(text)))

        def color_auth_word(word: str) -> Text:
            try:
                escaped_word = escape(str(word))
                lw = str(word).lower()
                if lw in FAILURE_TERMS:
                    return Text(escaped_word.upper(), style="red")
                elif lw in PASS_TERMS:
                    return Text(escaped_word, style="green")
                elif lw in WARNING_TERMS:
                    return Text(escaped_word, style="orange3")
                else:
                    return Text(escaped_word)
            except Exception:
                return Text(escape(str(word)))

        def color_authentication_results(value: str) -> Text:
            try:
                if not isinstance(value, str):
                    value = str(value)
                
                tokens = re.split(r'(\s+|;)', value)
                colored_tokens = []
                
                for token in tokens:
                    try:
                        if '=' in token:
                            mech, sep, status = token.partition('=')
                            colored_tokens.append(Text(escape(mech + sep)))
                            colored_tokens.append(color_auth_word(status))
                        else:
                            colored_tokens.append(Text(escape(token)))
                    except Exception:
                        colored_tokens.append(Text(escape(str(token))))

                result = Text()
                for t in colored_tokens:
                    try:
                        result.append(t)
                    except Exception:
                        continue

                # Apply IP highlighting only (no timestamps in auth results)
                try:
                    plain = result.plain
                    ip_matches = safe_regex_finditer(IP_PATTERN, plain)
                    for match in ip_matches:
                        result.stylize("yellow", match.start(), match.end())
                except Exception:
                    pass

                return result
            except Exception:
                return Text(escape(str(value)))

        def color_value(key: str, val: str) -> Text:
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
                    
                    # For basic headers, only highlight IPs, not timestamps
                    t = highlight_ips_only(display_text)
                    lw = val.lower()
                    
                    try:
                        if any(term in lw for term in FAILURE_TERMS):
                            return Text(escape(display_text).upper(), style="red")
                        elif any(term in lw for term in PASS_TERMS):
                            return Text(escape(display_text), style="green")
                        elif any(term in lw for term in WARNING_TERMS):
                            return Text(escape(display_text), style="orange3")
                    except Exception:
                        pass
                    
                    return t
            except Exception:
                return Text(escape(str(val)))

        # Display basic headers
        try:
            basics = ["From", "Return-Path", "Reply-To", "Message-ID", "Subject", "Date"]
            for key in basics:
                try:
                    val = safe_get_header(headers, key)
                    if not val or (isinstance(val, str) and not val.strip()):
                        print(color_key(key), Text("MISSING", style="red"))
                    else:
                        print(color_key(key), color_value(key, val))
                except Exception as e:
                    print(color_key(key), Text(f"ERROR: {e}", style="red"))
        except Exception as e:
            print(f"[red]Error displaying basic headers: {e}[/red]")

        print()

        # Display authentication results
        try:
            auth_results_val = safe_get_header(headers, "Authentication-Results")
            if auth_results_val:
                print(color_key("Authentication-Results"), color_value("Authentication-Results", auth_results_val))
            else:
                print(color_key("Authentication-Results"), Text("MISSING", style="red"))
        except Exception as e:
            print(color_key("Authentication-Results"), Text(f"ERROR: {e}", style="red"))

        print()

        # Display Received hops
        try:
            print(Text("Received Hops:", style="blue"))
            try:
                hops = msg_obj.get_all("Received", []) if hasattr(msg_obj, 'get_all') else []
                if not hops:
                    print("  No Received headers found")
                else:
                    for i, hop in enumerate(hops, 1):
                        try:
                            label = Text(f"[{i}]", style="blue")
                            hop_text = highlight_ips_and_dates_in_hops(str(hop))
                            print(label, hop_text)
                        except Exception as e:
                            print(f"  [{i}] Error processing hop: {e}")
            except Exception as e:
                print(f"  Error extracting Received headers: {e}")
        except Exception as e:
            print(f"[red]Error in Received hops analysis: {e}[/red]")

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
                    verdict = Text("Security concern unlikely, but verify other factors.", style="green")
                elif "red" in concerns or factors_malicious:
                    verdict = Text("Likely security concern. Proceed with caution.", style="red")
                else:
                    verdict = Text("Possible security concern detected.", style="orange3")
            except Exception:
                verdict = Text("Could not determine security assessment.", style="orange3")

            # Display factors
            if factors_benign:
                print("[green]Benign factors:[/green]")
                for f in factors_benign:
                    print(f"  • {escape(f)}")

            if factors_warn:
                print("[orange3]Warning factors:[/orange3]")
                for f in factors_warn:
                    print(f"  • {escape(f)}")

            if factors_malicious:
                print("[red]Malicious factors:[/red]")
                for f in factors_malicious:
                    print(f"  • {escape(f)}")

            if not (factors_benign or factors_warn or factors_malicious):
                print("  None detected.")

            print()
            print(Text("HEADER ASSESSMENT:", style="blue"), verdict)
            
        except Exception as e:
            print(f"[red]Error in security assessment: {e}[/red]")

    except Exception as e:
        print(f"[red]Critical error in header analysis: {e}[/red]")
        print("[yellow]Header analysis could not be completed.[/yellow]")