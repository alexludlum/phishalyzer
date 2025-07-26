from rich.console import Console
from rich.markup import escape
import re
from email.message import Message

console = Console()

def analyze_headers(msg: Message):
    issues = []

    console.print("\nHEADER SUMMARY\n", highlight=False)

    def safe_get(field):
        val = msg.get(field)
        if val is None or val.strip() == "":
            # Print missing headers as RED "MISSING"
            return "[red]MISSING[/red]"
        return val

    def print_header(key, value):
        # Print header key and value without extra blank line between them
        if value == "[red]MISSING[/red]":
            console.print(f"[blue]{escape(key)}[/] {value}", highlight=False)
        else:
            console.print(f"[blue]{escape(key)}[/] {value}", highlight=False)

    def highlight_specials(text):
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'

        date_time_pattern = (
            r'(?<!\S)(\d{4}[-./]\d{1,2}[-./]\d{1,2})(?!\S)'
            r'|(?<!\S)(\d{1,2}:\d{2}:\d{2}(?:\s?[-+]\d{4})?)(?!\S)'
            r'|(?<!\S)([A-Z][a-z]{2},\s\d{1,2}\s[A-Z][a-z]{2}\s\d{4}\s\d{2}:\d{2}:\d{2}\s(?:[-+]\d{4}|[A-Z]{3,4}))(?!\S)'
        )

        lines = text.splitlines()
        highlighted_lines = []
        for line in lines:
            if any(tag in line for tag in ['[red]', '[yellow]', '[green]', '[blue]']):
                escaped_line = line
            else:
                escaped_line = escape(line)

            # Highlight IPs first
            line_with_ips = re.sub(ip_pattern, lambda m: f"[yellow]{m.group(0)}[/yellow]", escaped_line)

            # Then highlight dates/times
            def date_time_replacer(match):
                for group in match.groups():
                    if group:
                        return f"[blue]{group}[/blue]"
                return match.group(0)

            line_final = re.sub(date_time_pattern, date_time_replacer, line_with_ips)
            highlighted_lines.append(line_final)

        return "\n".join(highlighted_lines)

    def color_auth_result(value: str) -> str:
        """Color authentication results green if 'pass' or 'present', red if fail/softfail/missing."""
        val_lower = value.lower()
        if any(x in val_lower for x in ['pass', 'present', 'success']):
            return f"[green]{escape(value)}[/green]"
        elif any(x in val_lower for x in ['fail', 'softfail', 'missing', 'not signed', 'none', 'temperror', 'permerror']):
            return f"[red]{escape(value.upper())}[/red]"
        else:
            # Default to blue for other values
            return f"[blue]{escape(value)}[/blue]"

    from_addr = safe_get("From")
    reply_to = safe_get("Reply-To")
    return_path = safe_get("Return-Path")
    spf = safe_get("Received-SPF")
    auth_results = safe_get("Authentication-Results")
    message_id = safe_get("Message-ID")
    dkim = safe_get("DKIM-Signature")
    received_headers = msg.get_all("Received", [])

    print_header("From:", from_addr)
    print_header("Return-Path:", return_path)
    if "[red]MISSING[/red]" not in (return_path, from_addr):
        if extract_domain(from_addr) != extract_domain(return_path):
            issues.append("Return-Path domain does not match From domain")

    print_header("Reply-To:", reply_to)
    if reply_to != "[red]MISSING[/red]" and from_addr != "[red]MISSING[/red]":
        if extract_domain(reply_to) != extract_domain(from_addr):
            issues.append("Reply-To domain suspiciously differs from From domain")

    spf_colored = highlight_specials(spf)
    spf_colored = re.sub(
        r'(pass|fail|softfail)', 
        lambda m: f"[green]{m.group(1)}[/green]" if m.group(1).lower() == 'pass' else f"[red]{m.group(1).upper()}[/red]", 
        spf_colored, flags=re.IGNORECASE
    )
    print_header("SPF:", spf_colored)
    if 'fail' in spf.lower() or 'softfail' in spf.lower():
        issues.append("SPF authentication failed or soft failed")

    dkim_status = 'present' if dkim != "[red]MISSING[/red]" else 'missing'
    print_header("DKIM:", color_auth_result(dkim_status))
    if dkim == "[red]MISSING[/red]":
        issues.append("Missing DKIM signature")

    if auth_results != "[red]MISSING[/red]":
        auth_results_colored = highlight_specials(auth_results)
        auth_results_colored = re.sub(
            r'(pass|fail|none|missing|permerror|temperror|softfail)', 
            lambda m: f"[green]{m.group(1)}[/green]" if m.group(1).lower() == 'pass' else f"[red]{m.group(1).upper()}[/red]",
            auth_results_colored, flags=re.IGNORECASE
        )
        print_header("Authentication-Results:", auth_results_colored)
    else:
        print_header("Authentication-Results:", color_auth_result('missing'))
        issues.append("Missing Authentication-Results header")

    print_header("Message-ID:", message_id)

    console.print("\nRECEIVED HOPS\n", highlight=False)
    for i, hop in enumerate(received_headers[::-1], 1):
        number = f"[blue][{i}][/blue]"
        console.print(f"{number} {highlight_specials(hop.strip())}", highlight=False)
        ip_matches = re.findall(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b', hop)
        for ip in ip_matches:
            if is_private_ip(ip):
                issues.append(f"Private IP address found in Received header: {ip}")

    console.print("\nSECURITY ISSUES\n", highlight=False)
    if issues:
        for issue in issues:
            console.print(f"- {escape(issue)}", highlight=False)
    else:
        console.print("No issues detected.", highlight=False)

def extract_domain(addr: str) -> str:
    match = re.search(r'@([^\s>]+)', addr)
    return match.group(1).lower() if match else ""

def is_private_ip(ip: str) -> bool:
    octets = list(map(int, ip.split(".")))
    return (
        octets[0] == 10 or
        (octets[0] == 172 and 16 <= octets[1] <= 31) or
        (octets[0] == 192 and octets[1] == 168)
    )