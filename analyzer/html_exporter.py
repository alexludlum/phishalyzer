"""
HTML Export module for phishalyzer.
Exports comprehensive analysis results to HTML format.
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
    """Escape HTML special characters."""
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

def clean_verdict_text(verdict_text):
    """Clean verdict text by removing reason explanations."""
    # Remove anything after " - " or " (" that contains explanatory text
    if " - " in verdict_text:
        verdict_text = verdict_text.split(" - ")[0]
    elif " (" in verdict_text and verdict_text.count("(") == 1:
        verdict_text = verdict_text.split(" (")[0]
    
    return verdict_text.strip()

def format_authentication_results(auth_text, use_defanged):
    """Format authentication results with proper HTML coloring."""
    if not auth_text:
        return "MISSING"
    
    # Apply defanging if requested
    if use_defanged:
        auth_text = apply_export_defanging(auth_text, True)
    
    # Escape HTML
    auth_text = escape_html(auth_text)
    
    # Apply color coding for authentication terms
    failure_terms = ["fail", "softfail", "temperror", "permerror", "invalid", "missing", "bad", "hardfail", "not", "signed"]
    pass_terms = ["pass", "bestguesspass"]
    warning_terms = ["neutral", "policy", "none", "unknown"]
    
    # Color failure terms red
    for term in failure_terms:
        pattern = rf'\b{re.escape(term)}\b'
        auth_text = re.sub(pattern, f'<span style="color: red; font-weight: bold;">{term}</span>', auth_text, flags=re.IGNORECASE)
    
    # Color pass terms green
    for term in pass_terms:
        pattern = rf'\b{re.escape(term)}\b'
        auth_text = re.sub(pattern, f'<span style="color: green; font-weight: bold;">{term}</span>', auth_text, flags=re.IGNORECASE)
    
    # Color warning terms orange
    for term in warning_terms:
        pattern = rf'\b{re.escape(term)}\b'
        auth_text = re.sub(pattern, f'<span style="color: orange; font-weight: bold;">{term}</span>', auth_text, flags=re.IGNORECASE)
    
    # Handle special multi-word cases
    auth_text = re.sub(r'\bnot\s+signed\b', '<span style="color: red; font-weight: bold;">not signed</span>', auth_text, flags=re.IGNORECASE)
    
    return auth_text

def generate_html_report(email_file_path, file_type, use_defanged=False):
    """Generate comprehensive HTML report from analysis results."""
    
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
    
    # Start building HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Analysis Report - {escape_html(email_filename)}</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            line-height: 1.6;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }}
        h2 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 5px;
            margin-top: 30px;
            margin-bottom: 15px;
        }}
        h3 {{
            color: #34495e;
            margin-top: 20px;
            margin-bottom: 10px;
        }}
        .info-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        .info-table th, .info-table td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        .info-table th {{
            background-color: #3498db;
            color: white;
            font-weight: bold;
        }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; font-weight: bold; }}
        .low {{ color: #f1c40f; font-weight: bold; }}
        .benign {{ color: #27ae60; font-weight: bold; }}
        .info {{ color: #3498db; font-weight: bold; }}
        .unchecked {{ color: #f39c12; }}
        .malicious {{ color: #e74c3c; font-weight: bold; }}
        .suspicious {{ color: #e67e22; font-weight: bold; }}
        .finding-item {{
            margin: 10px 0;
            padding: 10px;
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
            border-radius: 4px;
        }}
        .no-findings {{
            color: #27ae60;
            font-style: italic;
            padding: 10px;
            background-color: #d5f4e6;
            border-radius: 4px;
            margin: 10px 0;
        }}
        .hash-text {{
            font-family: 'Courier New', monospace;
            font-size: 11px;
            word-break: break-all;
            background-color: #f8f9fa;
            padding: 5px;
            border-radius: 3px;
        }}
        ul, ol {{
            margin-left: 20px;
        }}
        .hop-item {{
            margin: 5px 0;
            padding: 8px;
            background-color: #f8f9fa;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>EMAIL ANALYSIS REPORT</h1>
        
        <table class="info-table">
            <tr>
                <th colspan="2" style="text-align: center;">Report Details</th>
            </tr>
            <tr>
                <td><strong>Generated:</strong></td>
                <td>{timestamp}</td>
            </tr>
            <tr>
                <td><strong>File Name:</strong></td>
                <td>{escape_html(email_filename)}</td>
            </tr>
            <tr>
                <td><strong>File Size:</strong></td>
                <td>{file_size}</td>
            </tr>
            <tr>
                <td><strong>File Type:</strong></td>
                <td>{file_type.upper()}</td>
            </tr>
            <tr>
                <td><strong>SHA256 Hash:</strong></td>
                <td><div class="hash-text">{file_hash}</div></td>
            </tr>
            <tr>
                <td><strong>Output Format:</strong></td>
                <td>{'Defanged' if use_defanged else 'Fanged'}</td>
            </tr>
        </table>
"""

    # Email Header Analysis Section
    html_content += """
        <h2>📧 Email Header Analysis</h2>
"""
    
    # Basic email headers
    try:
        # Get email object to extract basic headers
        from . import parser
        msg_obj, _ = parser.load_email(email_file_path)
        
        basic_headers = {
            'From': msg_obj.get('From', 'MISSING'),
            'To': msg_obj.get('To', 'MISSING'),
            'Subject': msg_obj.get('Subject', 'MISSING'),
            'Date': msg_obj.get('Date', 'MISSING'),
            'Return-Path': msg_obj.get('Return-Path', 'MISSING'),
            'Reply-To': msg_obj.get('Reply-To', 'MISSING'),
            'Message-ID': msg_obj.get('Message-ID', 'MISSING')
        }
        
        html_content += '<div class="finding-item"><h3>Basic Headers</h3><ul>'
        for header, value in basic_headers.items():
            if value == 'MISSING':
                html_content += f'<li><strong>{header}:</strong> <span class="critical">MISSING</span></li>'
            else:
                escaped_value = escape_html(apply_export_defanging(value, use_defanged))
                html_content += f'<li><strong>{header}:</strong> {escaped_value}</li>'
        html_content += '</ul></div>'
        
        # Authentication Results
        auth_results = msg_obj.get('Authentication-Results', '')
        html_content += '<div class="finding-item"><h3>Authentication Results</h3>'
        if auth_results:
            formatted_auth = format_authentication_results(auth_results, use_defanged)
            html_content += f'<p>{formatted_auth}</p>'
        else:
            html_content += '<p class="critical">MISSING</p>'
        html_content += '</div>'
        
    except Exception as e:
        html_content += f'<div class="finding-item"><p class="critical">Error extracting headers: {escape_html(str(e))}</p></div>'
    
    # Routing Hops
    html_content += '<div class="finding-item"><h3>Email Routing Hops</h3>'
    if received_hops and len(received_hops) > 0:
        html_content += f'<p><strong>Found {len(received_hops)} routing hop{"s" if len(received_hops) != 1 else ""}:</strong></p><ol>'
        for hop in received_hops:
            # Strip ANSI codes and apply defanging
            raw_content = hop.get('raw', hop.get('content', 'No content'))
            # Remove ANSI color codes
            import re
            clean_content = re.sub(r'\033\[[0-9;]*m', '', str(raw_content))
            clean_content = apply_export_defanging(clean_content, use_defanged)
            escaped_content = escape_html(clean_content)
            html_content += f'<li class="hop-item">{escaped_content}</li>'
        html_content += '</ol>'
    else:
        html_content += '<p class="no-findings">No routing information found</p>'
    html_content += '</div>'

    # IP Address Analysis Section
    html_content += """
        <h2>🌐 IP Address Analysis</h2>
"""
    
    if ip_results and len(ip_results) > 0:
        # Group IPs by verdict
        malicious_ips = [ip for ip in ip_results if ip[2] == 'malicious']
        suspicious_ips = [ip for ip in ip_results if ip[2] == 'suspicious']
        benign_ips = [ip for ip in ip_results if ip[2] == 'benign']
        unchecked_ips = [ip for ip in ip_results if ip[2] == 'unchecked']
        
        if malicious_ips:
            html_content += '<div class="finding-item"><h3 class="malicious">Malicious IP Addresses</h3><ul>'
            for ip_data in malicious_ips:
                ip, country, verdict, comment = ip_data[:4]
                display_ip = apply_export_defanging(ip, use_defanged)
                html_content += f'<li><strong>IP:</strong> <span class="malicious">{escape_html(display_ip)}</span> ({escape_html(country)}) - {escape_html(comment)}</li>'
            html_content += '</ul></div>'
        
        if suspicious_ips:
            html_content += '<div class="finding-item"><h3 class="suspicious">Suspicious IP Addresses</h3><ul>'
            for ip_data in suspicious_ips:
                ip, country, verdict, comment = ip_data[:4]
                display_ip = apply_export_defanging(ip, use_defanged)
                html_content += f'<li><strong>IP:</strong> <span class="suspicious">{escape_html(display_ip)}</span> ({escape_html(country)}) - {escape_html(comment)}</li>'
            html_content += '</ul></div>'
        
        if unchecked_ips:
            html_content += '<div class="finding-item"><h3 class="unchecked">Unchecked IP Addresses</h3><ul>'
            for ip_data in unchecked_ips:
                ip, country, verdict, comment = ip_data[:4]
                display_ip = apply_export_defanging(ip, use_defanged)
                clean_verdict = clean_verdict_text(f"IP: {display_ip} ({country}) - Verdict: {verdict.upper()}")
                html_content += f'<li>{escape_html(clean_verdict)}</li>'
            html_content += '</ul></div>'
        
        if benign_ips:
            html_content += '<div class="finding-item"><h3 class="benign">Benign IP Addresses</h3><ul>'
            for ip_data in benign_ips:
                ip, country, verdict, comment = ip_data[:4]
                display_ip = apply_export_defanging(ip, use_defanged)
                html_content += f'<li><strong>IP:</strong> <span class="benign">{escape_html(display_ip)}</span> ({escape_html(country)}) - {escape_html(comment)}</li>'
            html_content += '</ul></div>'
    else:
        html_content += '<div class="no-findings">No IP addresses detected in email headers or body</div>'

    # URL Analysis Section
    html_content += """
        <h2>🔗 URL Analysis</h2>
"""
    
    if url_results and len(url_results) > 0:
        total_urls = sum(len(r.get('urls', [])) for r in url_results)
        html_content += f'<p><strong>Found {total_urls} URL{"s" if total_urls != 1 else ""} across {len(url_results)} domain{"s" if len(url_results) != 1 else ""}:</strong></p>'
        
        # Group by verdict
        malicious_domains = [r for r in url_results if r.get('verdict') == 'malicious']
        suspicious_domains = [r for r in url_results if r.get('verdict') == 'suspicious']
        benign_domains = [r for r in url_results if r.get('verdict') == 'benign']
        unchecked_domains = [r for r in url_results if r.get('verdict') == 'unchecked']
        
        if malicious_domains:
            html_content += '<div class="finding-item"><h3 class="malicious">Malicious Domains</h3><ul>'
            for result in malicious_domains:
                domain = result.get('domain', 'unknown')
                urls = result.get('urls', [])
                comment = result.get('comment', '')
                display_domain = apply_export_defanging(domain, use_defanged)
                html_content += f'<li><strong>{escape_html(display_domain)}</strong> ({len(urls)} URL{"s" if len(urls) != 1 else ""}) - {escape_html(comment)}<ul>'
                for url in urls[:3]:  # Show first 3 URLs
                    display_url = apply_export_defanging(url, use_defanged)
                    html_content += f'<li>{escape_html(display_url)}</li>'
                if len(urls) > 3:
                    html_content += f'<li><em>... and {len(urls) - 3} more</em></li>'
                html_content += '</ul></li>'
            html_content += '</ul></div>'
        
        if suspicious_domains:
            html_content += '<div class="finding-item"><h3 class="suspicious">Suspicious Domains</h3><ul>'
            for result in suspicious_domains:
                domain = result.get('domain', 'unknown')
                urls = result.get('urls', [])
                comment = result.get('comment', '')
                display_domain = apply_export_defanging(domain, use_defanged)
                html_content += f'<li><strong>{escape_html(display_domain)}</strong> ({len(urls)} URL{"s" if len(urls) != 1 else ""}) - {escape_html(comment)}<ul>'
                for url in urls[:3]:
                    display_url = apply_export_defanging(url, use_defanged)
                    html_content += f'<li>{escape_html(display_url)}</li>'
                if len(urls) > 3:
                    html_content += f'<li><em>... and {len(urls) - 3} more</em></li>'
                html_content += '</ul></li>'
            html_content += '</ul></div>'
        
        if unchecked_domains:
            html_content += '<div class="finding-item"><h3 class="unchecked">Unchecked Domains</h3><ul>'
            for result in unchecked_domains:
                domain = result.get('domain', 'unknown')
                urls = result.get('urls', [])
                display_domain = apply_export_defanging(domain, use_defanged)
                html_content += f'<li><strong>{escape_html(display_domain)}</strong> ({len(urls)} URL{"s" if len(urls) != 1 else ""})<ul>'
                for url in urls[:2]:
                    display_url = apply_export_defanging(url, use_defanged)
                    html_content += f'<li>{escape_html(display_url)}</li>'
                if len(urls) > 2:
                    html_content += f'<li><em>... and {len(urls) - 2} more</em></li>'
                html_content += '</ul></li>'
            html_content += '</ul></div>'
        
        if benign_domains:
            html_content += '<div class="finding-item"><h3 class="benign">Benign Domains</h3><ul>'
            for result in benign_domains:
                domain = result.get('domain', 'unknown')
                urls = result.get('urls', [])
                comment = result.get('comment', '')
                display_domain = apply_export_defanging(domain, use_defanged)
                html_content += f'<li><strong>{escape_html(display_domain)}</strong> ({len(urls)} URL{"s" if len(urls) != 1 else ""}) - {escape_html(comment)}</li>'
            html_content += '</ul></div>'
    else:
        html_content += '<div class="no-findings">No URLs detected in email headers or body</div>'

    # Email Body Analysis Section
    html_content += """
        <h2>📝 Email Body Analysis</h2>
"""
    
    if body_results and body_results.get('findings'):
        findings = body_results['findings']
        risk_score = body_results.get('risk_score', 0)
        
        # Risk score color
        if risk_score >= 70:
            score_color = "critical"
        elif risk_score >= 40:
            score_color = "high"
        else:
            score_color = "medium"
        
        html_content += f'<p><strong>Risk Score:</strong> <span class="{score_color}">{risk_score}/100</span></p>'
        
        # Group findings by risk level
        high_risk = {k: v for k, v in findings.items() if v.get('risk_level') == 'HIGH'}
        medium_risk = {k: v for k, v in findings.items() if v.get('risk_level') == 'MEDIUM'}
        low_risk = {k: v for k, v in findings.items() if v.get('risk_level') == 'LOW'}
        
        if high_risk:
            html_content += '<div class="finding-item"><h3 class="critical">High Risk Findings</h3><ul>'
            for finding in high_risk.values():
                name = finding.get('name', 'Unknown')
                description = finding.get('description', '')
                keywords = finding.get('matched_keywords', [])
                html_content += f'<li><strong>{escape_html(name)}:</strong> {escape_html(description)}<ul>'
                for kw in keywords[:5]:  # Show first 5 keywords
                    keyword_text = kw.get('keyword', '')
                    matched_text = kw.get('matched_text', keyword_text)
                    html_content += f'<li>"{escape_html(keyword_text)}" (found: "{escape_html(matched_text)}")</li>'
                if len(keywords) > 5:
                    html_content += f'<li><em>... and {len(keywords) - 5} more keywords</em></li>'
                html_content += '</ul></li>'
            html_content += '</ul></div>'
        
        if medium_risk:
            html_content += '<div class="finding-item"><h3 class="high">Medium Risk Findings</h3><ul>'
            for finding in medium_risk.values():
                name = finding.get('name', 'Unknown')
                description = finding.get('description', '')
                keywords = finding.get('matched_keywords', [])
                html_content += f'<li><strong>{escape_html(name)}:</strong> {escape_html(description)} ({len(keywords)} keyword{"s" if len(keywords) != 1 else ""})</li>'
            html_content += '</ul></div>'
        
        if low_risk:
            html_content += '<div class="finding-item"><h3 class="medium">Low Risk Findings</h3><ul>'
            for finding in low_risk.values():
                name = finding.get('name', 'Unknown')
                description = finding.get('description', '')
                keywords = finding.get('matched_keywords', [])
                html_content += f'<li><strong>{escape_html(name)}:</strong> {escape_html(description)} ({len(keywords)} keyword{"s" if len(keywords) != 1 else ""})</li>'
            html_content += '</ul></div>'
    else:
        html_content += '<div class="no-findings">No phishing content detected in email body</div>'

    # Attachment Analysis Section
    html_content += """
        <h2>📎 Attachment Analysis</h2>
"""
    
    if attachment_results and len(attachment_results) > 0:
        html_content += f'<p><strong>Found {len(attachment_results)} attachment{"s" if len(attachment_results) != 1 else ""}:</strong></p>'
        
        for i, attachment in enumerate(attachment_results, 1):
            filename = attachment.get('filename', f'attachment_{i}')
            file_size = attachment.get('size', 0)
            file_hash = attachment.get('hash', 'N/A')
            detected_type = attachment.get('detected_type', 'Unknown')
            is_spoofed = attachment.get('is_spoofed', False)
            threat_level = attachment.get('threat_level', 'low')
            vt_verdict = attachment.get('vt_verdict', 'unchecked')
            vt_comment = attachment.get('vt_comment', '')
            qr_analysis = attachment.get('qr_analysis', {})
            
            # Format file size
            if file_size > 0:
                if file_size >= 1024*1024:
                    size_str = f"{file_size / (1024*1024):.1f} MB"
                elif file_size >= 1024:
                    size_str = f"{file_size / 1024:.1f} KB"
                else:
                    size_str = f"{file_size} B"
            else:
                size_str = "0 B"
            
            html_content += f'<div class="finding-item"><h3>Attachment {i}: {escape_html(filename)}</h3>'
            html_content += f'<p><strong>Size:</strong> {size_str}</p>'
            html_content += f'<p><strong>Detected Type:</strong> {escape_html(str(detected_type))}</p>'
            
            if file_hash != 'N/A':
                display_hash = apply_export_defanging(file_hash, use_defanged)
                html_content += f'<p><strong>SHA256:</strong> <div class="hash-text">{escape_html(display_hash)}</div></p>'
            
            # VirusTotal verdict
            # Continuing from where the previous artifact left off...

            # VirusTotal verdict
            if vt_verdict == 'malicious':
                html_content += f'<p><strong>VirusTotal:</strong> <span class="malicious">{vt_verdict.upper()}</span> - {escape_html(vt_comment)}</p>'
            elif vt_verdict == 'suspicious':
                html_content += f'<p><strong>VirusTotal:</strong> <span class="suspicious">{vt_verdict.upper()}</span> - {escape_html(vt_comment)}</p>'
            elif vt_verdict == 'benign':
                html_content += f'<p><strong>VirusTotal:</strong> <span class="benign">{vt_verdict.upper()}</span> - {escape_html(vt_comment)}</p>'
            else:
                html_content += f'<p><strong>VirusTotal:</strong> <span class="unchecked">{vt_verdict.upper()}</span></p>'
            
            # Spoofing detection
            if is_spoofed:
                spoof_desc = attachment.get('spoof_description', 'File extension spoofing detected')
                if threat_level == 'critical':
                    html_content += f'<p><strong>⚠️ CRITICAL THREAT:</strong> <span class="critical">{escape_html(spoof_desc)}</span></p>'
                elif threat_level == 'high':
                    html_content += f'<p><strong>⚠️ HIGH RISK SPOOFING:</strong> <span class="high">{escape_html(spoof_desc)}</span></p>'
                else:
                    html_content += f'<p><strong>⚠️ SPOOFING ALERT:</strong> <span class="medium">{escape_html(spoof_desc)}</span></p>'
            
            # QR Code analysis
            if qr_analysis and qr_analysis.get('qr_found'):
                qr_results = qr_analysis.get('qr_results', [])
                html_content += f'<p><strong>🔍 QR Code Analysis:</strong> Found {len(qr_results)} QR code{"s" if len(qr_results) != 1 else ""}</p><ul>'
                
                for j, qr in enumerate(qr_results, 1):
                    if 'url' in qr:
                        url = qr['url']
                        verdict = qr.get('verdict', 'unchecked')
                        comment = qr.get('comment', '')
                        page = qr.get('page', 1)
                        
                        display_url = apply_export_defanging(url, use_defanged)
                        location_text = f"QR {j} (Page {page})" if page > 1 else f"QR {j}"
                        
                        if verdict == 'malicious':
                            html_content += f'<li><strong>{location_text}:</strong> <span class="malicious">{escape_html(display_url)}</span> - <span class="malicious">MALICIOUS</span> ({escape_html(comment)})</li>'
                        elif verdict == 'suspicious':
                            html_content += f'<li><strong>{location_text}:</strong> <span class="suspicious">{escape_html(display_url)}</span> - <span class="suspicious">SUSPICIOUS</span> ({escape_html(comment)})</li>'
                        elif verdict == 'benign':
                            html_content += f'<li><strong>{location_text}:</strong> <span class="benign">{escape_html(display_url)}</span> - <span class="benign">BENIGN</span> ({escape_html(comment)})</li>'
                        else:
                            html_content += f'<li><strong>{location_text}:</strong> <span class="unchecked">{escape_html(display_url)}</span> - <span class="unchecked">UNCHECKED</span></li>'
                    else:
                        # Non-URL QR code
                        data = qr.get('data', 'No data')
                        qr_type = qr.get('type', 'Unknown')
                        page = qr.get('page', 1)
                        location_text = f"QR {j} (Page {page})" if page > 1 else f"QR {j}"
                        html_content += f'<li><strong>{location_text}:</strong> {escape_html(data)} (Type: {escape_html(qr_type)})</li>'
                
                html_content += '</ul>'
            
            # Content analysis (if available)
            content_analysis = attachment.get('attachment_content_analysis', {})
            if content_analysis and content_analysis.get('findings'):
                findings = content_analysis['findings']
                risk_score = content_analysis.get('risk_score', 0)
                
                html_content += f'<p><strong>📄 Content Analysis:</strong> Risk Score {risk_score}/100</p><ul>'
                for finding in findings.values():
                    name = finding.get('name', 'Unknown')
                    risk_level = finding.get('risk_level', 'LOW')
                    keyword_count = finding.get('keyword_count', 0)
                    
                    if risk_level == 'HIGH':
                        html_content += f'<li><span class="critical">{escape_html(name)}</span> ({keyword_count} indicators)</li>'
                    elif risk_level == 'MEDIUM':
                        html_content += f'<li><span class="high">{escape_html(name)}</span> ({keyword_count} indicators)</li>'
                    else:
                        html_content += f'<li><span class="medium">{escape_html(name)}</span> ({keyword_count} indicators)</li>'
                html_content += '</ul>'
            
            html_content += '</div>'
    else:
        html_content += '<div class="no-findings">No attachments found in this email</div>'

    # Benign Findings Section
    html_content += """
        <h2>✅ Benign Findings</h2>
"""
    
    benign_findings = []
    
    # Collect benign findings from various analyses
    if ip_results:
        benign_ip_count = len([ip for ip in ip_results if ip[2] == 'benign'])
        if benign_ip_count > 0:
            benign_findings.append(f"{benign_ip_count} IP address{'es' if benign_ip_count != 1 else ''} verified as benign")
    
    if url_results:
        benign_url_count = len([r for r in url_results if r.get('verdict') == 'benign'])
        if benign_url_count > 0:
            benign_findings.append(f"{benign_url_count} domain{'s' if benign_url_count != 1 else ''} verified as benign")
    
    if attachment_results:
        benign_attachment_count = len([a for a in attachment_results if a.get('vt_verdict') == 'benign'])
        if benign_attachment_count > 0:
            benign_findings.append(f"{benign_attachment_count} attachment{'s' if benign_attachment_count != 1 else ''} verified as benign")
    
    # Add authentication successes if available
    try:
        from . import parser
        msg_obj, _ = parser.load_email(email_file_path)
        auth_results = msg_obj.get('Authentication-Results', '').lower()
        
        if 'spf=pass' in auth_results:
            benign_findings.append("SPF authentication passed")
        if 'dkim=pass' in auth_results:
            benign_findings.append("DKIM authentication passed")
        if 'dmarc=pass' in auth_results:
            benign_findings.append("DMARC authentication passed")
            
    except Exception:
        pass
    
    if benign_findings:
        html_content += '<div class="finding-item"><ul>'
        for finding in benign_findings:
            html_content += f'<li class="benign">{escape_html(finding)}</li>'
        html_content += '</ul></div>'
    else:
        html_content += '<div class="no-findings">No specific benign indicators identified</div>'

    # Close HTML
    html_content += """
        <hr style="margin-top: 40px; border: 1px solid #bdc3c7;">
        <p style="text-align: center; color: #7f8c8d; font-size: 12px; margin-top: 20px;">
            Report generated by Phishalyzer - Email Security Analysis Tool
        </p>
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
                output.print("[blue]1:[/blue] HTML Report")
                output.print("[blue]2:[/blue] Markdown Report (coming soon)")
                output.print("[blue]3:[/blue] Plaintext Report (coming soon)")
                output.print("[blue]4:[/blue] Return to main menu")
            else:
                print("\nExport Format:")
                print("1: HTML Report")
                print("2: Markdown Report (coming soon)")
                print("3: Plaintext Report (coming soon)")
                print("4: Return to main menu")
            
            try:
                choice = input("Enter option [1-4]: ").strip()
                if choice in ['1']:
                    format_type = 'html'
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
    """Main function to export analysis report."""
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
        if format_type == 'html':
            if COMPATIBLE_OUTPUT:
                print_status("Generating HTML report...", "info")
            else:
                print("Generating HTML report...")
            
            html_content = generate_html_report(file_path, file_type, use_defanged)
            
            # Generate filename
            email_filename = os.path.basename(file_path)
            sanitized_name = sanitize_filename(email_filename)
            timestamp = datetime.datetime.now().strftime("%Y.%m.%d")
            base_filename = f"{sanitized_name}_analysis_report_{timestamp}"
            
            # Get desktop path and create unique filename
            desktop_path = get_desktop_path()
            output_path = get_unique_filename(desktop_path, base_filename, 'html')
            
            # Write file
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                if COMPATIBLE_OUTPUT:
                    print_status(f"HTML report saved successfully!", "success")
                    output.print(f"[blue]File location:[/blue] {output_path}")
                    
                    # Show file size
                    file_size = os.path.getsize(output_path)
                    if file_size >= 1024:
                        size_str = f"{file_size / 1024:.1f} KB"
                    else:
                        size_str = f"{file_size} B"
                    output.print(f"[blue]File size:[/blue] {size_str}")
                else:
                    print(f"HTML report saved successfully!")
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
            print_status(f"Error generating export report: {e}", "error")
        else:
            print(f"Error generating export report: {e}")

# Add this function to update the main phishalyzer.py file to track the analyzed file
def track_analyzed_file(file_path, file_type):
    """Store the analyzed file information for export purposes."""
    try:
        import sys
        main_module = sys.modules.get('__main__') or sys.modules.get('phishalyzer')
        if main_module:
            setattr(main_module, 'last_analyzed_file_path', file_path)
            setattr(main_module, 'last_analyzed_file_type', file_type)
    except Exception:
        pass