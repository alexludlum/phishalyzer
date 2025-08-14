"""
Complete Terminal-style HTML Export module for phishalyzer.
Matches terminal output exactly with proper color coding and formatting.
"""

import os
import re
import hashlib
import datetime
from pathlib import Path

# Import compatible output system
try:
    from .compatible_output import output, print_status
    COMPATIBLE_OUTPUT = True
except ImportError:
    COMPATIBLE_OUTPUT = False

# Import defanging functionality
try:
    from . import defanger
    DEFANGER_AVAILABLE = True
except ImportError:
    DEFANGER_AVAILABLE = False

def get_desktop_path():
    """Get the user's desktop path across different operating systems."""
    try:
        home = Path.home()
        
        # Try different desktop paths
        desktop_paths = [
            home / "Desktop",
            home / "desktop", 
            home / "Schreibtisch",  # German
            home / "Bureau",        # French
            home / "Escritorio",    # Spanish
        ]
        
        for desktop_path in desktop_paths:
            if desktop_path.exists() and desktop_path.is_dir():
                return str(desktop_path)
        
        # Fallback to home directory
        return str(home)
        
    except Exception:
        # Ultimate fallback to current directory
        return os.getcwd()

def sanitize_filename(filename):
    """Sanitize filename by removing problematic characters."""
    if not filename:
        return "email_analysis"
    
    # Remove file extension if present
    name_without_ext = os.path.splitext(filename)[0]
    
    # Replace problematic characters with underscores
    sanitized = re.sub(r'[<>:"/\\|?*\s]', '_', name_without_ext)
    
    # Remove multiple consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized)
    
    # Remove leading/trailing underscores
    sanitized = sanitized.strip('_')
    
    # Ensure it's not empty and not too long
    if not sanitized:
        sanitized = "email_analysis"
    elif len(sanitized) > 50:
        sanitized = sanitized[:50]
    
    return sanitized

def get_unique_filename(base_path, base_name, extension):
    """Generate a unique filename by appending a counter if file exists."""
    counter = 1
    original_path = os.path.join(base_path, f"{base_name}.{extension}")
    
    if not os.path.exists(original_path):
        return original_path
    
    while True:
        new_path = os.path.join(base_path, f"{base_name}_{counter}.{extension}")
        if not os.path.exists(new_path):
            return new_path
        counter += 1

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of the original email file."""
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception as e:
        return f"Error calculating hash: {e}"

def get_file_size(file_path):
    """Get formatted file size."""
    try:
        size_bytes = os.path.getsize(file_path)
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        size = float(size_bytes)
        
        while size >= 1024.0 and i < len(size_names) - 1:
            size /= 1024.0
            i += 1
        
        return f"{size:.1f} {size_names[i]}"
    except Exception:
        return "Unknown size"

def apply_export_defanging(text, use_defanged):
    """Apply defanging based on user's export choice."""
    if not use_defanged or not DEFANGER_AVAILABLE:
        return str(text)
    return defanger.defang_text(str(text))

def escape_html(text):
    """Escape HTML special characters but preserve line breaks."""
    if not isinstance(text, str):
        text = str(text)
    
    replacements = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;'
    }
    
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    
    return text

def colorize_text(text, color):
    """Add terminal-style color to text."""
    color_map = {
        'red': 'terminal-red',
        'green': 'terminal-green',
        'yellow': 'terminal-yellow',
        'blue': 'terminal-blue',
        'magenta': 'terminal-magenta',
        'cyan': 'terminal-cyan',
        'orange': 'terminal-orange',
        'orange3': 'terminal-orange',
        'white': 'terminal-white'
    }
    
    css_class = color_map.get(color, 'terminal-white')
    return f'<span class="{css_class}">{escape_html(str(text))}</span>'

def format_section_header(title):
    """Format a section header exactly like the terminal output."""
    total_width = 50
    title_with_spaces = f" {title.upper()} "
    padding_needed = total_width - len(title_with_spaces)
    left_padding = padding_needed // 2
    right_padding = padding_needed - left_padding
    header_line = "=" * left_padding + title_with_spaces + "=" * right_padding
    return f'\n\n{colorize_text(header_line, "magenta")}\n\n'

def format_ip_with_colors(text, use_defanged):
    """Color-code IP addresses and timestamps in text like terminal output."""
    # Apply defanging first if requested
    if use_defanged:
        text = apply_export_defanging(text, True)
    
    # Escape HTML
    text = escape_html(text)
    
    # Color IP addresses (yellow)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    defanged_ip_pattern = r'\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b'
    
    text = re.sub(ip_pattern, lambda m: colorize_text(m.group(0), 'yellow'), text)
    text = re.sub(defanged_ip_pattern, lambda m: colorize_text(m.group(0), 'yellow'), text)
    
    # Color timestamps (blue) - comprehensive patterns
    timestamp_patterns = [
        r'\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\b',
        r'\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\b',
        r'\b\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\b'
    ]
    
    for pattern in timestamp_patterns:
        text = re.sub(pattern, lambda m: colorize_text(m.group(0), 'blue'), text)
    
    return text

def format_authentication_results(auth_text, use_defanged):
    """Format authentication results with exact terminal colors."""
    if not auth_text:
        return colorize_text("MISSING", "red")
    
    # Apply defanging if requested
    if use_defanged:
        auth_text = apply_export_defanging(auth_text, True)
    
    # Escape HTML
    auth_text = escape_html(auth_text)
    
    # Color authentication terms exactly like terminal
    failure_terms = ["fail", "softfail", "temperror", "permerror", "invalid", "missing", "bad", "hardfail", "not"]
    pass_terms = ["pass", "bestguesspass"]
    warning_terms = ["neutral", "policy", "none", "unknown"]
    
    # Color failure terms red
    for term in failure_terms:
        pattern = rf'\b{re.escape(term)}\b'
        auth_text = re.sub(pattern, lambda m: colorize_text(m.group(0), 'red'), auth_text, flags=re.IGNORECASE)
    
    # Color pass terms green
    for term in pass_terms:
        pattern = rf'\b{re.escape(term)}\b'
        auth_text = re.sub(pattern, lambda m: colorize_text(m.group(0), 'green'), auth_text, flags=re.IGNORECASE)
    
    # Color warning terms orange
    for term in warning_terms:
        pattern = rf'\b{re.escape(term)}\b'
        auth_text = re.sub(pattern, lambda m: colorize_text(m.group(0), 'orange'), auth_text, flags=re.IGNORECASE)
    
    # Handle special cases
    auth_text = re.sub(r'\bnot\s+signed\b', lambda m: colorize_text(m.group(0), 'red'), auth_text, flags=re.IGNORECASE)
    
    # Color IP addresses in authentication results
    auth_text = format_ip_with_colors(auth_text, False)  # Don't double-defang
    
    return auth_text

def safe_format_file_size(size_bytes):
    """Format file size exactly like the terminal output."""
    try:
        if not isinstance(size_bytes, (int, float)) or size_bytes < 0:
            return "Unknown size"
        
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        size = float(size_bytes)
        
        while size >= 1024.0 and i < len(size_names) - 1:
            size /= 1024.0
            i += 1
        
        return f"{size:.1f} {size_names[i]}"
    except Exception:
        return "Unknown size"

def generate_comprehensive_terminal_html(email_file_path, file_type, use_defanged=False):
    """Generate HTML that exactly matches terminal output with complete formatting."""
    
    # Get global analysis results
    try:
        import sys
        main_module = sys.modules.get('__main__') or sys.modules.get('phishalyzer')
        if not main_module:
            raise Exception("Cannot access main module for analysis results")
        
        # Get all analysis results
        url_results = getattr(main_module, 'last_url_analysis_results', None)
        body_results = getattr(main_module, 'last_body_analysis_results', None)
        attachment_results = getattr(main_module, 'last_attachment_results', None)
        received_hops = getattr(main_module, 'last_received_hops', None)
        ip_results = getattr(main_module, 'last_ip_analysis_results', None)
        header_analysis = getattr(main_module, 'last_header_analysis', None)
        
    except Exception as e:
        raise Exception(f"Error accessing analysis results: {e}")
    
    # Calculate file details
    email_filename = os.path.basename(email_file_path)
    file_size = get_file_size(email_file_path)
    file_hash = calculate_file_hash(email_file_path)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Start building HTML with exact terminal styling
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishalyzer Analysis Report - {escape_html(email_filename)}</title>
    <style>
        body {{
            background-color: #0c0c0c;
            color: #cccccc;
            font-family: 'Courier New', 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            line-height: 1.4;
            margin: 0;
            padding: 20px;
            white-space: pre-wrap;
        }}
        
        .terminal-container {{
            background-color: #0c0c0c;
            border: 1px solid #333333;
            border-radius: 5px;
            padding: 20px;
            max-width: none;
            overflow-x: auto;
        }}
        
        /* Exact terminal color classes */
        .terminal-red {{ color: #cd3131; font-weight: bold; }}
        .terminal-green {{ color: #0dbc79; font-weight: bold; }}
        .terminal-yellow {{ color: #e5e510; font-weight: bold; }}
        .terminal-blue {{ color: #2472c8; font-weight: bold; }}
        .terminal-magenta {{ color: #bc3fbc; font-weight: bold; }}
        .terminal-cyan {{ color: #11a8cd; font-weight: bold; }}
        .terminal-orange {{ color: #ff8c00; font-weight: bold; }}
        .terminal-white {{ color: #e5e5e5; }}
        
        .report-header {{
            border-bottom: 1px solid #333333;
            padding-bottom: 20px;
            margin-bottom: 20px;
        }}
        
        a {{ color: #3b8eea; }}
    </style>
</head>
<body>
    <div class="terminal-container">
        <div class="report-header">
{colorize_text("EMAIL ANALYSIS REPORT", "blue")}

Generated: {timestamp}
File: {escape_html(email_filename)}
Size: {file_size}
Type: {file_type.upper()}
SHA256: {file_hash}
Output: {'Defanged' if use_defanged else 'Fanged'}
        </div>
"""

    # Email Header Analysis Section
    html_content += format_section_header("EMAIL HEADER ANALYSIS")
    
    try:
        # Load email to get basic headers
        from . import parser
        msg_obj, _ = parser.load_email(email_file_path)
        
        # Basic headers with exact terminal formatting
        headers_to_show = [
            ('From', msg_obj.get('From', '')),
            ('Return-Path', msg_obj.get('Return-Path', '')),
            ('Reply-To', msg_obj.get('Reply-To', '')),
            ('Message-ID', msg_obj.get('Message-ID', '')),
            ('Subject', msg_obj.get('Subject', '')),
            ('Date', msg_obj.get('Date', ''))
        ]
        
        for header_name, header_value in headers_to_show:
            if not header_value or not header_value.strip():
                html_content += f"{colorize_text(f'{header_name}:', 'blue')} {colorize_text('MISSING', 'red')}\n"
            else:
                display_value = apply_export_defanging(header_value, use_defanged)
                # Color IP addresses in headers
                display_value = format_ip_with_colors(display_value, False)
                html_content += f"{colorize_text(f'{header_name}:', 'blue')} {display_value}\n"
        
        html_content += "\n"
        
        # Authentication Results with exact formatting
        auth_results = msg_obj.get('Authentication-Results', '')
        formatted_auth = format_authentication_results(auth_results, use_defanged)
        html_content += f"{colorize_text('Authentication-Results:', 'blue')} {formatted_auth}\n\n"
        
        # Routing hops with exact terminal formatting
        if received_hops and len(received_hops) > 0:
            html_content += f"Found {colorize_text(str(len(received_hops)), 'blue')} routing hop{'s' if len(received_hops) != 1 else ''}:\n\n"
            for hop in received_hops:
                index = hop.get('index', '?')
                raw_content = hop.get('raw', hop.get('content', 'No content'))
                # Remove ANSI codes and apply defanging and coloring
                clean_content = re.sub(r'\033\[[0-9;]*m', '', str(raw_content))
                colored_content = format_ip_with_colors(clean_content, use_defanged)
                html_content += f"{colorize_text(f'[{index}]', 'blue')} {colored_content}\n"
        else:
            html_content += f"{colorize_text('No routing information found', 'yellow')}\n"
            html_content += f"{colorize_text('This may indicate header sanitization or local processing', 'blue')}\n"
        
    except Exception as e:
        html_content += f"{colorize_text(f'Error extracting headers: {str(e)}', 'red')}\n"

    # IP Address Analysis Section
    html_content += format_section_header("IP ADDRESS ANALYSIS")
    
    if ip_results and len(ip_results) > 0:
        for ip_data in ip_results:
            if len(ip_data) >= 4:
                ip, country, verdict, comment = ip_data[:4]
                display_ip = apply_export_defanging(ip, use_defanged)
                
                verdict_color = {
                    'malicious': 'red', 
                    'suspicious': 'orange', 
                    'benign': 'green', 
                    'unchecked': 'orange'
                }.get(verdict, 'white')
                
                html_content += f"IP: {colorize_text(display_ip, 'yellow')} ({escape_html(country)}) - Verdict: {colorize_text(verdict.upper(), verdict_color)} ({escape_html(comment)})\n"
    else:
        html_content += f"{colorize_text('IP address analysis completed successfully.', 'green')}\n"
        html_content += f"{colorize_text('No IP addresses were detected in the email.', 'green')}\n"
        html_content += "This indicates:\n"
        html_content += "- Clean email headers and body\n"
        html_content += "- No embedded IP addresses found\n"
        html_content += "- Network infrastructure details may have been sanitized\n"

    # URL Analysis Section  
    html_content += format_section_header("URL ANALYSIS")
    
    if url_results and len(url_results) > 0:
        total_urls = sum(len(r.get('urls', [])) for r in url_results)
        html_content += f"Found {colorize_text(str(total_urls), 'blue')} URL{'s' if total_urls != 1 else ''} across {colorize_text(str(len(url_results)), 'blue')} domain{'s' if len(url_results) != 1 else ''}:\n\n"
        
        # Group by verdict and display exactly like terminal
        verdict_groups = [
            ('malicious', 'red', 'MALICIOUS DOMAINS'),
            ('suspicious', 'orange', 'SUSPICIOUS DOMAINS'), 
            ('unchecked', 'orange', 'UNCHECKED DOMAINS'),
            ('benign', 'green', 'BENIGN DOMAINS')
        ]
        
        for verdict_type, color, section_name in verdict_groups:
            verdict_domains = [r for r in url_results if r.get('verdict') == verdict_type]
            if verdict_domains:
                html_content += f"{colorize_text(f'{section_name} ({len(verdict_domains)}):', color)}\n"
                for result in verdict_domains:
                    domain = result.get('domain', 'unknown')
                    urls = result.get('urls', [])
                    comment = result.get('comment', '')
                    display_domain = apply_export_defanging(domain, use_defanged)
                    
                    html_content += f"- {escape_html(display_domain)} ({len(urls)} URL{'s' if len(urls) != 1 else ''}) - {escape_html(comment)}\n"
                    
                    # Show sample URLs
                    if result.get('representative_url'):
                        display_url = apply_export_defanging(result['representative_url'], use_defanged)
                        html_content += f"  Sample: {escape_html(display_url)}\n"
                html_content += "\n"
    else:
        html_content += f"{colorize_text('URL analysis completed successfully.', 'green')}\n"
        html_content += f"{colorize_text('No URLs were detected in the email body or headers.', 'green')}\n"
        html_content += "This could indicate:\n"
        html_content += "- Clean email with no external links\n"
        html_content += "- URLs may be obfuscated or embedded within attachments\n"
        html_content += "- Manual verification may still be needed\n"

    # Email Body Analysis Section
    html_content += format_section_header("EMAIL BODY ANALYSIS")
    
    if body_results and body_results.get('findings'):
        findings = body_results['findings']
        risk_score = body_results.get('risk_score', 0)
        
        score_color = 'red' if risk_score >= 70 else 'orange' if risk_score >= 40 else 'yellow'
        html_content += f"Found potential phishing content (Risk score: {colorize_text(f'{risk_score}/100', score_color)}):\n"
        
        # Sort by risk level exactly like terminal
        risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_findings = sorted(findings.values(), key=lambda x: (risk_order.get(x.get("risk_level", "LOW"), 3), x.get("name", "")))
        
        for finding in sorted_findings:
            risk_level = finding.get('risk_level', 'LOW')
            name = finding.get('name', 'Unknown')
            keywords = finding.get('matched_keywords', [])
            
            risk_color = {'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow'}.get(risk_level, 'white')
            
            # Format exactly like terminal: "- [LEVEL]: Name: keywords"
            html_content += f"- [{colorize_text(risk_level, risk_color)}]: {escape_html(name)}: "
            
            # Show keywords exactly like terminal
            keyword_texts = []
            for kw in keywords[:5]:  # Show first 5
                keyword_text = kw.get('keyword', '')
                matched_text = kw.get('matched_text', keyword_text)
                if kw.get('exact_match'):
                    keyword_texts.append(f'"{keyword_text}"')
                else:
                    keyword_texts.append(f'"{matched_text}"')
            
            html_content += ", ".join(keyword_texts)
            if len(keywords) > 5:
                html_content += f", +{len(keywords) - 5} more"
            html_content += "\n"
    else:
        html_content += f"{colorize_text('No phishing phrases detected in email body.', 'green')}\n"

    # Attachment Analysis Section - COMPLETE
    html_content += format_section_header("ATTACHMENT ANALYSIS")
    
    if attachment_results and len(attachment_results) > 0:
        html_content += f"Found {colorize_text(str(len(attachment_results)), 'blue')} attachment{'s' if len(attachment_results) != 1 else ''}:\n\n"
        
        for i, attachment in enumerate(attachment_results, 1):
            filename = attachment.get('filename', f'attachment_{i}')
            content_type = attachment.get('content_type', 'unknown')
            size = attachment.get('size', 0)
            file_hash = attachment.get('hash', 'N/A')
            detected_type = attachment.get('detected_type')
            vt_verdict = attachment.get('vt_verdict', 'unchecked')
            vt_comment = attachment.get('vt_comment', '')
            threat_level = attachment.get('threat_level', 'low')
            is_spoofed = attachment.get('is_spoofed', False)
            spoof_description = attachment.get('spoof_description', '')
            
            # Attachment header exactly like terminal
            html_content += f"{colorize_text(f'Attachment {i}:', 'blue')}\n"
            html_content += f"- Filename: {colorize_text(escape_html(filename), 'yellow')}\n"
            
            # Type with detected type info
            if detected_type and detected_type != 'unknown':
                type_info = f"{content_type} (detected: {detected_type.upper()})"
            else:
                type_info = content_type
            html_content += f"- Type: {escape_html(type_info)}\n"
            
            # Size
            size_str = safe_format_file_size(size)
            html_content += f"- Size: {size_str}\n"
            
            # SHA256 with color coding by verdict
            if file_hash != "N/A":
                display_hash = apply_export_defanging(file_hash, use_defanged)
                hash_color = {
                    'malicious': 'red', 'suspicious': 'yellow', 'benign': 'green',
                    'unknown': 'orange', 'unchecked': 'orange'
                }.get(vt_verdict, 'orange')
                html_content += f"- SHA256: {colorize_text(escape_html(display_hash), hash_color)}\n"
            
            # VirusTotal verdict with colors
            verdict_color = {
                'malicious': 'red', 'suspicious': 'yellow', 'benign': 'green',
                'unknown': 'orange', 'unchecked': 'orange'
            }.get(vt_verdict, 'orange')
            html_content += f"- VirusTotal: {colorize_text(vt_verdict.upper(), verdict_color)} ({escape_html(vt_comment)})\n"
            
            html_content += "\n"
            
            # Content analysis if available
            content_analysis = attachment.get('attachment_content_analysis', {})
            if content_analysis and content_analysis.get('text_extracted'):
                text_length = content_analysis.get('text_length', 0)
                html_content += f"{colorize_text('Text extracted:', 'blue')} {text_length} characters\n"
                
                # URL analysis in content
                url_analysis = content_analysis.get('url_analysis', {})
                if url_analysis and url_analysis.get('results'):
                    total_urls = url_analysis.get('urls_found', 0)
                    total_domains = url_analysis.get('domains_found', 0)
                    malicious_count = url_analysis.get('malicious_count', 0)
                    suspicious_count = url_analysis.get('suspicious_count', 0)
                    
                    html_content += f"- URLs in content: {total_urls} URL{'s' if total_urls != 1 else ''} across {total_domains} domain{'s' if total_domains != 1 else ''}\n"
                    
                    if malicious_count > 0:
                        html_content += f"- {colorize_text(f'{malicious_count} malicious domain' + ('s' if malicious_count != 1 else '') + ' detected!', 'red')}\n"
                    if suspicious_count > 0:
                        html_content += f"- {colorize_text(f'{suspicious_count} suspicious domain' + ('s' if suspicious_count != 1 else '') + ' detected', 'orange')}\n"
            
            # Spoofing detection with threat levels
            if is_spoofed:
                if threat_level == 'critical':
                    html_content += f"  {colorize_text('CRITICAL THREAT:', 'red')} {escape_html(spoof_description)}\n"
                elif threat_level == 'high':
                    html_content += f"  {colorize_text('HIGH RISK SPOOFING:', 'red')} {escape_html(spoof_description)}\n"
                else:
                    html_content += f"  {colorize_text('SPOOFING ALERT:', 'orange')} {escape_html(spoof_description)}\n"
                html_content += "\n"
            
            # QR Code analysis
            qr_analysis = attachment.get('qr_analysis', {})
            if qr_analysis and qr_analysis.get('qr_found'):
                qr_results = qr_analysis.get('qr_results', [])
                html_content += f"{colorize_text('QR Code Detected! Details:', 'red')}\n"
                
                for j, qr in enumerate(qr_results, 1):
                    if 'url' in qr:
                        url = qr['url']
                        verdict = qr.get('verdict', 'unchecked')
                        comment = qr.get('comment', '')
                        page = qr.get('page', 1)
                        
                        display_url = apply_export_defanging(url, use_defanged)
                        location_text = f"QR {j} (Page {page}) Destination:" if page > 1 else f"QR {j} Destination:"
                        verdict_color = {'malicious': 'red', 'suspicious': 'yellow', 'benign': 'green', 'unchecked': 'orange'}.get(verdict, 'white')
                        
                        html_content += f"- {location_text} {colorize_text(escape_html(display_url), 'yellow')}\n"
                        html_content += f"- Verdict: {colorize_text(verdict.upper(), verdict_color)} ({escape_html(comment)})\n"
                html_content += "\n"
            
            # Risk Level assessment exactly like terminal
            final_risk_level = attachment.get('final_risk_level', 'unknown')
            final_risk_reason = attachment.get('final_risk_reason', '')
            
            html_content += "Risk Level:\n"
            
            # Determine QR status
            # Continuing from where the previous artifact left off...

            # Determine QR status
            qr_status = ""
            if qr_analysis and qr_analysis.get('qr_found'):
                qr_results = qr_analysis.get('qr_results', [])
                malicious_qr = any(qr.get('verdict') == 'malicious' for qr in qr_results if isinstance(qr, dict))
                suspicious_qr = any(qr.get('verdict') == 'suspicious' for qr in qr_results if isinstance(qr, dict))
                
                if malicious_qr:
                    qr_status = " (Malicious QR code detected)"
                elif suspicious_qr:
                    qr_status = " (Suspicious QR code detected)"
                else:
                    qr_status = " (QR code detected)"
            
            # Risk level with proper colors
            risk_color = {
                'critical': 'red',
                'high': 'red',
                'medium': 'orange',
                'low': 'green',
                'unknown': 'orange'
            }.get(final_risk_level, 'orange')
            
            html_content += f"- {colorize_text(final_risk_level.upper() + qr_status, risk_color)}\n"
            
            # Show specific risk factors
            content_analysis = attachment.get('attachment_content_analysis', {})
            risk_factors = []
            
            # Get content analysis risks
            if content_analysis and content_analysis.get('findings'):
                findings = content_analysis['findings']
                high_risk_findings = [f for f in findings.values() if f.get('risk_level') == 'HIGH']
                if high_risk_findings:
                    for finding in high_risk_findings[:2]:  # Show first 2
                        risk_factors.append(f"PHISHING CONTENT: {finding.get('name', 'Unknown')}")
            
            # Get spoofing risks
            if is_spoofed:
                if threat_level == 'critical':
                    risk_factors.append(f"CRITICAL SPOOFING: {spoof_description}")
                elif threat_level == 'high':
                    risk_factors.append(f"HIGH RISK SPOOFING: {spoof_description}")
                else:
                    risk_factors.append(f"EXTENSION SPOOFING: {spoof_description}")
            
            # Get other risks
            if final_risk_reason and not qr_status and not is_spoofed:
                if not any(factor in final_risk_reason for factor in ['QR code', 'EXTENSION SPOOFING', 'CRITICAL SPOOFING']):
                    risk_factors.append(final_risk_reason)
            
            # Display risk factors
            for factor in risk_factors:
                if factor.startswith('CRITICAL'):
                    html_content += f"- {colorize_text(escape_html(factor), 'red')}\n"
                elif factor.startswith('MALICIOUS') or factor.startswith('HIGH RISK'):
                    html_content += f"- {colorize_text(escape_html(factor), 'red')}\n"
                elif factor.startswith('PHISHING CONTENT'):
                    html_content += f"- {colorize_text(escape_html(factor), 'red')}\n"
                elif 'suspicious' in factor.lower():
                    html_content += f"- {colorize_text(escape_html(factor), 'orange')}\n"
                else:
                    html_content += f"- {escape_html(factor)}\n"
            
            # Add content risk score if available
            if content_analysis and content_analysis.get('risk_score', 0) > 0:
                content_risk_score = content_analysis['risk_score']
                score_color = 'red' if content_risk_score >= 70 else 'orange' if content_risk_score >= 40 else 'yellow'
                html_content += f"- Content risk score: {colorize_text(f'{content_risk_score}/100', score_color)}\n"
            
            html_content += "\n"
        
        # Summary assessment exactly like terminal
        try:
            final_high_risk_count = sum(1 for r in attachment_results if r.get('final_risk_level') == 'high')
            final_critical_count = sum(1 for r in attachment_results if r.get('final_risk_level') == 'critical')
            malicious_count = sum(1 for r in attachment_results if r.get('vt_verdict') == 'malicious')
            suspicious_count = sum(1 for r in attachment_results if r.get('vt_verdict') == 'suspicious')
            spoofed_count = sum(1 for r in attachment_results if r.get('is_spoofed'))
            
            # Count QR codes
            total_qr_count = 0
            for r in attachment_results:
                qr_analysis = r.get('qr_analysis', {})
                if qr_analysis and qr_analysis.get('qr_found'):
                    qr_results = qr_analysis.get('qr_results', [])
                    total_qr_count += len(qr_results)
            
            qr_codes_found = total_qr_count > 0
            
            # Check for phishing content in attachments
            phishing_files_count = sum(1 for r in attachment_results 
                                     if r.get('attachment_content_analysis', {}).get('findings'))
            malicious_url_files = sum(1 for r in attachment_results 
                                    if r.get('attachment_content_analysis', {}).get('url_analysis', {}).get('malicious_count', 0) > 0)
            
            # Determine overall threat level exactly like terminal
            threat_factors = []
            summary_color = "green"  # Default to safe
            
            # HIGHEST PRIORITY: Critical threats
            if final_critical_count > 0:
                threat_factors.append(f"{final_critical_count} CRITICAL threat{'s' if final_critical_count != 1 else ''} (spoofed executables/PDFs)")
                summary_color = "red"
            
            if malicious_count > 0:
                threat_factors.append(f"{malicious_count} malicious file{'s' if malicious_count != 1 else ''} (VirusTotal)")
                if summary_color != "red":
                    summary_color = "red"
            
            if malicious_url_files > 0:
                threat_factors.append(f"{malicious_url_files} file{'s' if malicious_url_files != 1 else ''} with malicious URLs")
                if summary_color not in ["red"]:
                    summary_color = "red"
            
            if spoofed_count > 0:
                threat_factors.append(f"{spoofed_count} spoofed file{'s' if spoofed_count != 1 else ''}")
                if summary_color not in ["red"]:
                    summary_color = "red"
            
            if phishing_files_count > 0:
                threat_factors.append(f"{phishing_files_count} file{'s' if phishing_files_count != 1 else ''} with phishing content")
                if summary_color not in ["red"]:
                    summary_color = "red"
            
            if qr_codes_found:
                if total_qr_count == 1:
                    threat_factors.append("QR code detected")
                else:
                    threat_factors.append(f"{total_qr_count} QR codes detected")
                if summary_color not in ["red"]:
                    summary_color = "red"
            
            if suspicious_count > 0:
                threat_factors.append(f"{suspicious_count} suspicious file{'s' if suspicious_count != 1 else ''} (VirusTotal)")
                if summary_color not in ["red"]:
                    summary_color = "orange"
            
            if final_high_risk_count > 0 and summary_color not in ["red", "orange"]:
                summary_color = "orange"
            
            # Generate summary text exactly like terminal
            if threat_factors:
                if final_critical_count > 0:
                    summary_text = f"CRITICAL SECURITY THREAT: {threat_factors[0]}"
                    if len(threat_factors) > 1:
                        summary_text += f" + {len(threat_factors) - 1} more threat{'s' if len(threat_factors) - 1 != 1 else ''}!"
                    else:
                        summary_text += "!"
                elif len(threat_factors) == 1:
                    summary_text = f"HIGH RISK: {threat_factors[0]}!"
                elif len(threat_factors) == 2:
                    summary_text = f"HIGH RISK: {threat_factors[0]} and {threat_factors[1]}!"
                else:
                    summary_text = f"HIGH RISK: {threat_factors[0]}, {threat_factors[1]}, and {len(threat_factors) - 2} more threat{'s' if len(threat_factors) - 2 != 1 else ''}!"
            else:
                summary_text = "Attachments appear benign, but verify manually."
                summary_color = "green"
            
            html_content += f"{colorize_text('ATTACHMENT ASSESSMENT:', 'blue')} {colorize_text(summary_text, summary_color)}\n"
            
        except Exception as e:
            html_content += f"{colorize_text(f'Error generating summary assessment: {e}', 'red')}\n"
        
    else:
        html_content += f"{colorize_text('No attachments found in this email.', 'green')}\n"

    # Executive Summary if available
    if any([url_results, body_results, attachment_results]):
        html_content += format_section_header("EXECUTIVE FINDINGS REPORT")
        
        # Use the existing comprehensive findings function
        try:
            main_module = sys.modules.get('__main__') or sys.modules.get('phishalyzer')
            if main_module and hasattr(main_module, 'compile_comprehensive_findings'):
                comprehensive_findings = main_module.compile_comprehensive_findings()
                
                # Critical Threats Section
                if comprehensive_findings.get('critical_threats'):
                    html_content += f"{colorize_text('CRITICAL SECURITY THREATS:', 'red')}\n"
                    for threat in comprehensive_findings['critical_threats']:
                        html_content += f"• {escape_html(threat)}\n"
                    html_content += "\n"
                
                # High Risk Indicators Section
                if comprehensive_findings.get('high_risk_indicators'):
                    html_content += f"{colorize_text('HIGH RISK INDICATORS:', 'red')}\n"
                    for indicator in comprehensive_findings['high_risk_indicators']:
                        html_content += f"• {escape_html(indicator)}\n"
                    html_content += "\n"
                
                # Suspicious Activity Section
                if comprehensive_findings.get('suspicious_activity'):
                    html_content += f"{colorize_text('SUSPICIOUS ACTIVITY:', 'orange')}\n"
                    for activity in comprehensive_findings['suspicious_activity']:
                        html_content += f"• {escape_html(activity)}\n"
                    html_content += "\n"
                
                # Manual Verification Required Section
                if comprehensive_findings.get('manual_verification_required'):
                    html_content += f"{colorize_text('ITEMS REQUIRING MANUAL VERIFICATION:', 'yellow')}\n"
                    for item in comprehensive_findings['manual_verification_required']:
                        html_content += f"• {escape_html(item)}\n"
                    html_content += "\n"
                
                # Authentication & Infrastructure Concerns Section
                if comprehensive_findings.get('authentication_infrastructure_concerns'):
                    html_content += f"{colorize_text('AUTHENTICATION & INFRASTRUCTURE CONCERNS:', 'orange')}\n"
                    for concern in comprehensive_findings['authentication_infrastructure_concerns']:
                        html_content += f"• {escape_html(concern)}\n"
                    html_content += "\n"
                
                # Final Verdict Section
                if hasattr(main_module, 'determine_final_verdict'):
                    verdict, reasons = main_module.determine_final_verdict(comprehensive_findings)
                    
                    # Color the verdict based on risk level
                    if "CRITICAL" in verdict:
                        verdict_color = "red"
                    elif "HIGH" in verdict:
                        verdict_color = "red"
                    elif "MEDIUM" in verdict:
                        verdict_color = "orange"
                    else:
                        verdict_color = "yellow"
                    
                    html_content += f"{colorize_text('FINAL VERDICT:', 'blue')} {colorize_text(verdict, verdict_color)}\n"
                    
                    for reason in reasons:
                        html_content += f"• {escape_html(reason)}\n"
                
                # Show nothing found message only if truly nothing was found
                total_findings = (len(comprehensive_findings.get('critical_threats', [])) + 
                                len(comprehensive_findings.get('high_risk_indicators', [])) + 
                                len(comprehensive_findings.get('suspicious_activity', [])) + 
                                len(comprehensive_findings.get('manual_verification_required', [])) + 
                                len(comprehensive_findings.get('authentication_infrastructure_concerns', [])))
                
                if total_findings == 0:
                    html_content += f"\n{colorize_text('No significant security concerns identified in automated analysis.', 'green')}\n"
                    html_content += f"{colorize_text('Email appears to be legitimate based on available threat intelligence.', 'green')}\n"
                    
        except Exception as e:
            html_content += f"{colorize_text(f'Error generating executive summary: {e}', 'red')}\n"

    # Close HTML
    html_content += """
    </div>
</body>
</html>"""

    return html_content

def prompt_export_format():
    """Prompt user for export format and defanging preference."""
    try:
        # Format selection
        while True:
            if COMPATIBLE_OUTPUT:
                output.print("\n[blue]Export Format:[/blue]")
                output.print("[blue]1:[/blue] Terminal-style HTML Report")
                output.print("[blue]2:[/blue] Markdown Report (coming soon)")
                output.print("[blue]3:[/blue] Plaintext Report (coming soon)")
                output.print("[blue]4:[/blue] Return to main menu")
            else:
                print("\nExport Format:")
                print("1: Terminal-style HTML Report")
                print("2: Markdown Report (coming soon)")
                print("3: Plaintext Report (coming soon)")
                print("4: Return to main menu")
            
            try:
                choice = input("Enter option [1-4]: ").strip()
                if choice in ['1']:
                    format_type = 'terminal-html'
                    break
                elif choice in ['2', '3']:
                    if COMPATIBLE_OUTPUT:
                        print_status("This format is not yet implemented.", "warning")
                    else:
                        print("This format is not yet implemented.")
                    continue
                elif choice in ['4', '']:
                    return None, None
                else:
                    print("Invalid input. Please enter 1, 2, 3, or 4.")
                    continue
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")
                return None, None
        
        # Defanging preference
        while True:
            if COMPATIBLE_OUTPUT:
                output.print("\n[blue]Output Style:[/blue]")
                output.print("[blue]1:[/blue] Fanged (normal URLs/IPs)")
                output.print("[blue]2:[/blue] Defanged (safe URLs/IPs)")
            else:
                print("\nOutput Style:")
                print("1: Fanged (normal URLs/IPs)")
                print("2: Defanged (safe URLs/IPs)")
            
            try:
                style_choice = input("Enter option [1-2]: ").strip()
                if style_choice == '1':
                    use_defanged = False
                    break
                elif style_choice == '2':
                    use_defanged = True
                    break
                else:
                    print("Invalid input. Please enter 1 or 2.")
                    continue
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")
                return None, None
        
        return format_type, use_defanged
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error in export format selection: {e}", "error")
        else:
            print(f"Error in export format selection: {e}")
        return None, None

def export_analysis_report():
    """Main function to export analysis report in terminal style."""
    try:
        # Check if analysis has been run
        import sys
        main_module = sys.modules.get('__main__') or sys.modules.get('phishalyzer')
        if not main_module:
            if COMPATIBLE_OUTPUT:
                print_status("Error: Cannot access analysis results.", "error")
            else:
                print("Error: Cannot access analysis results.")
            return
        
        # Check if we have the original file path
        if not hasattr(main_module, 'last_analyzed_file_path'):
            if COMPATIBLE_OUTPUT:
                print_status("Error: No email file has been analyzed yet. Run an analysis first.", "warning")
            else:
                print("Error: No email file has been analyzed yet. Run an analysis first.")
            return
        
        file_path = getattr(main_module, 'last_analyzed_file_path')
        file_type = getattr(main_module, 'last_analyzed_file_type', 'unknown')
        
        if not file_path or not os.path.exists(file_path):
            if COMPATIBLE_OUTPUT:
                print_status("Error: Original email file not found. Re-run analysis.", "error")
            else:
                print("Error: Original email file not found. Re-run analysis.")
            return
        
        # Get export preferences
        format_type, use_defanged = prompt_export_format()
        if not format_type:
            return  # User cancelled
        
        # Generate report
        if format_type == 'terminal-html':
            if COMPATIBLE_OUTPUT:
                print_status("Generating terminal-style HTML report...", "info")
            else:
                print("Generating terminal-style HTML report...")
            
            html_content = generate_comprehensive_terminal_html(file_path, file_type, use_defanged)
            
            # Generate filename
            email_filename = os.path.basename(file_path)
            sanitized_name = sanitize_filename(email_filename)
            timestamp = datetime.datetime.now().strftime("%Y.%m.%d")
            base_filename = f"{sanitized_name}_terminal_report_{timestamp}"
            
            # Get desktop path and create unique filename
            desktop_path = get_desktop_path()
            output_path = get_unique_filename(desktop_path, base_filename, 'html')
            
            # Write file
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                if COMPATIBLE_OUTPUT:
                    print_status(f"Terminal-style HTML report saved successfully!", "success")
                    output.print(f"[blue]File location:[/blue] {output_path}")
                    
                    # Show file size
                    file_size = os.path.getsize(output_path)
                    if file_size >= 1024:
                        size_str = f"{file_size / 1024:.1f} KB"
                    else:
                        size_str = f"{file_size} B"
                    output.print(f"[blue]File size:[/blue] {size_str}")
                else:
                    print(f"Terminal-style HTML report saved successfully!")
                    print(f"File location: {output_path}")
                    
                    file_size = os.path.getsize(output_path)
                    if file_size >= 1024:
                        size_str = f"{file_size / 1024:.1f} KB"
                    else:
                        size_str = f"{file_size} B"
                    print(f"File size: {size_str}")
                
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error saving report: {e}", "error")
                else:
                    print(f"Error saving report: {e}")
                return
        
        # Return prompt
        try:
            input("\nPress Enter to return to main menu...")
        except (KeyboardInterrupt, EOFError):
            pass
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error generating terminal-style export report: {e}", "error")
        else:
            print(f"Error generating terminal-style export report: {e}")