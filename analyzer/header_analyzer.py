import re
import shutil
from email.message import Message
from rich import print
from rich.text import Text

IP_PATTERN = re.compile(
    r'\b('
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'
    r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
    r')\b'
)

DATE_PATTERN = re.compile(
    r'\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+'
    r'\d{1,2}\s+'
    r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'\d{4}'
    r'(?:\s+\d{2}:\d{2}(?::\d{2})?\s+[-+]\d{4})?'
    r'\b'
)

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

def print_centered_header(text="EMAIL HEADER ANALYSIS"):
    term_width = shutil.get_terminal_size().columns
    max_width = min(term_width, 80)
    header_line = "=" * max_width
    padding = (max_width - len(text)) // 2
    if padding < 0:
        padding = 0
    print(header_line)
    print(" " * padding + text)
    print(header_line + "\n")

def analyze_headers(msg_obj: Message):
    headers = dict(msg_obj.items())

    def color_key(key: str) -> Text:
        return Text(key + ":", style="blue")

    def highlight_ips_and_dates(text: str) -> Text:
        t = Text(text)
        for match in IP_PATTERN.finditer(text):
            t.stylize("yellow", match.start(), match.end())
        for match in DATE_PATTERN.finditer(text):
            t.stylize("blue", match.start(), match.end())
        return t

    def color_auth_word(word: str) -> Text:
        lw = word.lower()
        if lw in FAILURE_TERMS:
            return Text(word.upper(), style="red")
        elif lw in PASS_TERMS:
            return Text(word, style="green")
        elif lw in WARNING_TERMS:
            return Text(word, style="orange3")
        else:
            return Text(word)

    def color_authentication_results(value: str) -> Text:
        tokens = re.split(r'(\s+|;)', value)
        colored_tokens = []
        for token in tokens:
            if '=' in token:
                mech, sep, status = token.partition('=')
                colored_tokens.append(Text(mech + sep))
                colored_tokens.append(color_auth_word(status))
            else:
                colored_tokens.append(Text(token))

        result = Text()
        for t in colored_tokens:
            result.append(t)

        plain = result.plain
        for match in IP_PATTERN.finditer(plain):
            result.stylize("yellow", match.start(), match.end())
        for match in DATE_PATTERN.finditer(plain):
            result.stylize("blue", match.start(), match.end())

        return result

    def color_value(key: str, val: str) -> Text:
        if key == "Authentication-Results":
            return color_authentication_results(val)
        else:
            t = highlight_ips_and_dates(val)
            lw = val.lower()
            if any(term in lw for term in FAILURE_TERMS):
                return Text(val.upper(), style="red")
            elif any(term in lw for term in PASS_TERMS):
                return Text(val, style="green")
            elif any(term in lw for term in WARNING_TERMS):
                return Text(val, style="orange3")
            return t

    print_centered_header()

    basics = ["From", "Return-Path", "Reply-To", "Message-ID", "Subject", "Date"]
    for key in basics:
        val = headers.get(key)
        if val is None or (isinstance(val, str) and not val.strip()):
            print(color_key(key), Text("MISSING", style="red"))
        else:
            print(color_key(key), color_value(key, val))

    print()

    auth_results_val = headers.get("Authentication-Results")
    if auth_results_val is not None:
        print(color_key("Authentication-Results"), color_value("Authentication-Results", auth_results_val))
    else:
        print(color_key("Authentication-Results"), Text("MISSING", style="red"))

    print()

    print(Text("Received Hops:", style="blue"))
    hops = msg_obj.get_all("Received", [])
    for i, hop in enumerate(hops, 1):
        label = Text(f"[{i}]", style="blue")
        hop_text = Text(hop)
        for match in IP_PATTERN.finditer(hop):
            hop_text.stylize("yellow", match.start(), match.end())
        for match in DATE_PATTERN.finditer(hop):
            hop_text.stylize("blue", match.start(), match.end())
        print(label, hop_text)

    print()

    concerns = []
    factors_benign = []
    factors_warn = []
    factors_malicious = []

    def get_auth_result(mech: str):
        auth_res = headers.get("Authentication-Results", "").lower()
        m = re.search(rf"{mech}=([a-z]+)", auth_res)
        if m:
            return m.group(1)
        else:
            return None

    for mech in ["spf", "dkim", "dmarc"]:
        result = get_auth_result(mech)
        if not result:
            result = "missing"
        if result in FAILURE_TERMS:
            concerns.append("red")
            factors_malicious.append(f"{mech.upper()}: Failure or missing (value: {result})")
        elif result in WARNING_TERMS:
            concerns.append("orange")
            text = f"{mech.upper()}: Warning or Suspect (value: {result})"
            factors_warn.append(text)
        elif result in PASS_TERMS:
            concerns.append("green")
            factors_benign.append(f"{mech.upper()}: Passed (value: {result})")
        else:
            concerns.append("orange")
            factors_warn.append(f"{mech.upper()}: Ambiguous or unknown result (value: {result})")

    reply_to = headers.get("Reply-To")
    if reply_to is None or not reply_to.strip():
        factors_warn.append("Reply-To header missing")
    else:
        factors_benign.append("Reply-To header present")

    from_addr = headers.get("From", "").lower()
    return_path = headers.get("Return-Path", "").lower()
    if from_addr and return_path and return_path not in from_addr:
        factors_warn.append("Return-Path domain does not match the From domain (possible spoofing)")

    if all(c == "green" for c in concerns) and not factors_warn and not factors_malicious:
        verdict = Text("Security concern unlikely, but verify other factors.", style="green")
    elif "red" in concerns or factors_malicious:
        verdict = Text("Likely security concern. Proceed with caution.", style="red")
    else:
        verdict = Text("Possible security concern detected.", style="orange3")

    if factors_benign:
        print("[green]Benign factors:[/green]")
        for f in factors_benign:
            print(f"  • {f}")

    if factors_warn:
        print("[orange3]Warning factors:[/orange3]")
        for f in factors_warn:
            print(f"  • {f}")

    if factors_malicious:
        print("[red]Malicious factors:[/red]")
        for f in factors_malicious:
            print(f"  • {f}")

    if not (factors_benign or factors_warn or factors_malicious):
        print("  None detected.")

    print()
    print(Text("HEADER ASSESSMENT:", style="blue"), verdict)
    print()
