"""
Comprehensive report generator for phishalyzer email analysis results.
Generates professional plaintext reports suitable for customer delivery with cybersecurity expertise.
"""

import os
import hashlib
import platform
import re
from datetime import datetime

# Import compatible output and defanging systems
try:
    from .compatible_output import output
    COMPATIBLE_OUTPUT = True
except ImportError:
    COMPATIBLE_OUTPUT = False

try:
    from . import defanger
    DEFANGER_AVAILABLE = True
except ImportError:
    DEFANGER_AVAILABLE = False

def get_desktop_path():
    """Get the desktop path for Windows, Mac, and Linux."""
    system = platform.system()
    if system == "Windows":
        return os.path.join(os.path.expanduser("~"), "Desktop")
    elif system == "Darwin":  # macOS
        return os.path.join(os.path.expanduser("~"), "Desktop")
    else:  # Linux and others
        # Try common desktop locations
        desktop_paths = [
            os.path.join(os.path.expanduser("~"), "Desktop"),
            os.path.join(os.path.expanduser("~"), "desktop"),
            os.path.expanduser("~")  # fallback to home directory
        ]
        for path in desktop_paths:
            if os.path.exists(path):
                return path
        return os.path.expanduser("~")  # ultimate fallback

def format_section_header(title, total_width=75):
    """Create section header with consistent total width."""
    title_with_spaces = f" {title.upper()} "
    padding_needed = total_width - len(title_with_spaces)
    left_padding = padding_needed // 2
    right_padding = padding_needed - left_padding
    return "=" * left_padding + title_with_spaces + "=" * right_padding

def safe_defang_for_report(text, output_mode):
    """Apply defanging to text based on output mode."""
    try:
        if not text or not isinstance(text, str):
            return str(text) if text is not None else ""
        
        # Use the passed output_mode parameter directly
        if output_mode == "defanged":
            result = str(text)
            
            # Replace protocols
            result = result.replace('https://', 'https[:]//') 
            result = result.replace('http://', 'http[:]//') 
            result = result.replace('ftp://', 'ftp[:]//') 
            
            # Replace dots in domains - comprehensive list
            domain_replacements = [
                ('.com', '[.]com'),
                ('.net', '[.]net'),
                ('.org', '[.]org'),
                ('.edu', '[.]edu'),
                ('.gov', '[.]gov'),
                ('.mil', '[.]mil'),
                ('.int', '[.]int'),
                ('.co.', '[.]co[.]'),
                ('.uk', '[.]uk'),
                ('.de', '[.]de'),
                ('.fr', '[.]fr'),
                ('.io', '[.]io'),
                ('.me', '[.]me'),
                ('.ru', '[.]ru'),
                ('.cn', '[.]cn'),
                ('.jp', '[.]jp'),
                ('.au', '[.]au'),
                ('.ca', '[.]ca'),
                ('.info', '[.]info'),
                ('.biz', '[.]biz'),
                ('.tv', '[.]tv'),
                ('.cc', '[.]cc'),
                ('.se', '[.]se'),  # Added for Swedish domains
                ('.one', '[.]one')   # Added for .one domains
            ]
            
            for original, replacement in domain_replacements:
                result = result.replace(original, replacement)
            
            # Defang IPv4 addresses
            result = re.sub(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b', r'\1[.]\2[.]\3[.]\4', result)
            
            return result
        else:
            return str(text)
    except Exception:
        return str(text)

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of the original email file."""
    try:
        if not file_path or not os.path.exists(file_path):
            return "N/A"
        
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error: {e}"

def safe_format_file_size(size_bytes):
    """Format file size with error handling."""
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

def extract_main_headers_from_msg(msg_obj):
    """Extract main email headers for display in report."""
    try:
        if not msg_obj:
            return {}
        
        headers_to_extract = [
            'From', 'Return-Path', 'Reply-To', 'Message-ID', 
            'Subject', 'Date', 'Authentication-Results'
        ]
        
        extracted_headers = {}
        for header_name in headers_to_extract:
            try:
                value = msg_obj.get(header_name, '')
                if value and str(value).strip():
                    extracted_headers[header_name] = str(value).strip()
                else:
                    extracted_headers[header_name] = "MISSING"
            except Exception:
                extracted_headers[header_name] = "ERROR"
        
        return extracted_headers
    except Exception:
        return {}

def format_header_analysis_section(analysis_results, output_mode):
    """Format header analysis with complete header display and routing details."""
    try:
        lines = []
        
        # Section header with proper spacing
        lines.append("")
        lines.append("")  # TWO blank lines before section
        lines.append(format_section_header("EMAIL HEADER ANALYSIS"))
        lines.append("")  # ONE blank line after header
        
        # Extract headers from stored message object
        headers_displayed = False
        try:
            import sys
            main_module = sys.modules.get('__main__') or sys.modules.get('phishalyzer')
            if main_module and hasattr(main_module, 'last_analyzed_msg_obj'):
                msg_obj = getattr(main_module, 'last_analyzed_msg_obj', None)
                if msg_obj:
                    headers = extract_main_headers_from_msg(msg_obj)
                    
                    # Display main headers with defanging
                    for header_name in ['From', 'Return-Path', 'Reply-To', 'Message-ID', 'Subject', 'Date']:
                        value = headers.get(header_name, 'MISSING')
                        display_value = safe_defang_for_report(value, output_mode)
                        lines.append(f"{header_name}: {display_value}")
                    
                    # Authentication Results
                    auth_results = headers.get('Authentication-Results', 'MISSING')
                    if auth_results != 'MISSING':
                        display_auth = safe_defang_for_report(auth_results, output_mode)
                        lines.append(f"Authentication-Results: {display_auth}")
                    else:
                        lines.append("Authentication-Results: MISSING")
                    
                    lines.append("")  # Blank line after headers
                    headers_displayed = True
        except Exception as e:
            pass
        
        if not headers_displayed:
            # This should not happen now, but keep as fallback
            lines.append("Email headers: [Unable to extract - check original file]")
            lines.append("")
        
        # Routing hops
        routing_hops = analysis_results.get('routing_hops', [])
        if routing_hops and len(routing_hops) > 0:
            lines.append(f"Total hops identified: {len(routing_hops)}")
            
            for hop in routing_hops:
                hop_index = hop.get('index', '?')
                hop_content = hop.get('raw', hop.get('content', ''))
                
                # Clean ANSI color codes from hop content
                clean_content = re.sub(r'\033\[[0-9;]*m', '', str(hop_content))
                # Apply defanging to the entire hop content
                display_content = safe_defang_for_report(clean_content, output_mode)
                
                lines.append(f"[{hop_index}] {display_content}")
        else:
            lines.append("No routing information available")
        
        return lines
    
    except Exception as e:
        return [f"Error formatting header analysis: {e}", ""]
    
def format_ip_analysis_section(analysis_results, output_mode):
    """Format IP analysis with simplified customer-ready output."""
    try:
        lines = []
        
        # Section header - TWO blank lines before
        lines.append("")
        lines.append("")
        lines.append(format_section_header("IP ADDRESS ANALYSIS"))
        lines.append("")  # ONE blank line after
        
        ip_results = analysis_results.get('ip_analysis', [])
        if ip_results and len(ip_results) > 0:
            # Process IP results into categories
            unchecked_ips = []
            benign_ips = []
            malicious_ips = []
            suspicious_ips = []
            
            for ip_data in ip_results:
                if ip_data and isinstance(ip_data, (list, tuple)) and len(ip_data) >= 3:
                    ip, country, verdict = ip_data[:3]
                    comment = ip_data[3] if len(ip_data) > 3 else ""
                    
                    # Apply defanging consistently
                    display_ip = safe_defang_for_report(ip, output_mode)
                    
                    if verdict.lower() == 'malicious':
                        malicious_ips.append(f"- {display_ip} ({country}) - {comment}")
                    elif verdict.lower() == 'suspicious':
                        suspicious_ips.append(f"- {display_ip} ({country}) - {comment}")
                    elif verdict.lower() == 'benign':
                        benign_ips.append(f"- {display_ip} ({country}) - Benign")
                    else:
                        if country == 'Private':
                            unchecked_ips.append(f"- {display_ip} ({country}) - Private network")
                        else:
                            unchecked_ips.append(f"- {display_ip} ({country}) - [Analyst to verify]")
            
            # Display by threat level - NO blank lines between different categories
            all_entries = []
            if malicious_ips:
                all_entries.append("MALICIOUS IP ADDRESSES:")
                all_entries.extend(malicious_ips)
            if suspicious_ips:
                all_entries.append("SUSPICIOUS IP ADDRESSES:")
                all_entries.extend(suspicious_ips)
            if unchecked_ips:
                all_entries.extend(unchecked_ips)
            if benign_ips:
                all_entries.extend(benign_ips)
            
            lines.extend(all_entries)
        else:
            lines.append("No IP addresses detected in the email.")
        
        return lines
    
    except Exception as e:
        return [f"Error formatting IP analysis: {e}", ""]

def format_url_analysis_section(analysis_results, output_mode):
    """Format URL analysis with main FQDNs only, customer-ready output."""
    try:
        lines = []
        
        # Section header - TWO blank lines before
        lines.append("")
        lines.append("")
        lines.append(format_section_header("URL ANALYSIS"))
        lines.append("")  # ONE blank line after
        
        url_results = analysis_results.get('url_analysis', [])
        
        if not url_results:
            lines.append("No URLs detected in email body or headers.")
        else:
            # Process URL results - show only main domains
            all_entries = []
            for result in url_results:
                if result and isinstance(result, dict):
                    domain = result.get('domain', 'unknown')
                    verdict = result.get('verdict', 'unknown')
                    comment = result.get('comment', '')
                    
                    display_domain = safe_defang_for_report(domain, output_mode)
                    
                    if verdict == 'malicious':
                        all_entries.append(f"- {display_domain} - {comment}")
                    elif verdict == 'suspicious':
                        all_entries.append(f"- {display_domain} - {comment}")
                    elif verdict == 'benign':
                        all_entries.append(f"- {display_domain} - Benign")
                    else:
                        if domain not in ['malformed-urls', 'truncated-urls', 'unknown']:
                            all_entries.append(f"- {display_domain} - [Analyst to verify]")

            # Add all entries without blank lines
            lines.extend(all_entries)
        
        return lines
    
    except Exception as e:
        return [f"Error formatting URL analysis: {e}", ""]

def format_body_analysis_section(analysis_results):
    """Format body analysis with simplified customer-ready output."""
    try:
        lines = []
        
        # Section header - TWO blank lines before
        lines.append("")
        lines.append("")
        lines.append(format_section_header("EMAIL BODY ANALYSIS"))
        lines.append("")  # ONE blank line after
        
        body_results = analysis_results.get('body_analysis', {})
        
        if not body_results or not body_results.get('findings'):
            lines.append("No phishing patterns detected in email content.")
        else:
            # Process detailed body analysis results
            findings = body_results.get('findings', {})
            
            if findings:
                # Group findings by risk level
                risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
                sorted_findings = sorted(findings.values(), 
                                       key=lambda x: (risk_order.get(x.get("risk_level", "LOW"), 3), 
                                                     x.get("name", "")))
                
                current_risk_level = None
                for finding in sorted_findings:
                    risk_level = finding.get('risk_level', 'UNKNOWN')
                    name = finding.get('name', 'Unknown')
                    description = finding.get('description', '')
                    keyword_count = finding.get('keyword_count', 0)
                    matched_keywords = finding.get('matched_keywords', [])
                    
                    # Check if this is a new risk level
                    if current_risk_level != risk_level:
                        current_risk_level = risk_level
                        lines.append(f"{risk_level} RISK CONTENT: {name}.")
                        lines.append(f"- {description}")
                    else:
                        # Multiple findings in same risk level - shouldn't happen with current format
                        lines.append(f"- {name} ({keyword_count} indicator{'s' if keyword_count != 1 else ''})")
                        lines.append(f"  Description: {description}")
                    
                    # Show sample matched keywords - FIXED TEXT
                    if matched_keywords:
                        sample_keywords = []
                        for kw in matched_keywords[:3]:  # Show first 3
                            if isinstance(kw, dict):
                                keyword_text = kw.get('keyword', '')
                                matched_text = kw.get('matched_text', '')
                                if kw.get('exact_match', False):
                                    sample_keywords.append(f'"{keyword_text}"')
                                else:
                                    sample_keywords.append(f'"{matched_text}"')
                            else:
                                sample_keywords.append(f'"{str(kw)}"')
                        
                        if sample_keywords:
                            # FIXED: Change "Sample indicators:" to "Found in body:"
                            lines.append(f"- Found in body: {', '.join(sample_keywords)}")
                            if len(matched_keywords) > 3:
                                remaining = len(matched_keywords) - 3
                                lines.append(f"- ... and {remaining} more")
                    
                    # Add blank line between different risk levels only
                    next_finding_index = sorted_findings.index(finding) + 1
                    if (next_finding_index < len(sorted_findings) and 
                        sorted_findings[next_finding_index].get('risk_level') != risk_level):
                        lines.append("")
        
        return lines
    
    except Exception as e:
        return [f"Error formatting body analysis: {e}", ""]

def format_attachment_analysis_section(analysis_results, output_mode):
    """Format attachment analysis with customer-ready output."""
    try:
        lines = []
        
        # Section header - TWO blank lines before
        lines.append("")
        lines.append("")
        lines.append(format_section_header("ATTACHMENT ANALYSIS"))
        lines.append("")  # ONE blank line after
        
        attachment_results = analysis_results.get('attachment_analysis', [])
        if not attachment_results:
            lines.append("No attachments found in this email.")
            return lines
        
        valid_attachments = [a for a in attachment_results if a is not None and isinstance(a, dict)]
        if not valid_attachments:
            lines.append("No valid attachments to analyze.")
            return lines
        
        for i, att in enumerate(valid_attachments, 1):
            filename = att.get('filename', 'unknown')
            content_type = att.get('content_type', 'application/octet-stream')
            detected_type = att.get('detected_type')
            size = att.get('size', 0)
            file_hash = att.get('hash', 'N/A')
            vt_verdict = att.get('vt_verdict', 'unknown')
            vt_comment = att.get('vt_comment', '')
            is_spoofed = att.get('is_spoofed', False)
            spoof_description = att.get('spoof_description', '')
            threat_level = att.get('threat_level', 'low')
            
            lines.append(f"Attachment {i}:")
            lines.append(f"- Filename: {filename}")
            
            # Type with detected type if different
            if detected_type and detected_type.upper() != content_type:
                lines.append(f"- Type: {content_type} (detected: {detected_type.upper()})")
            else:
                lines.append(f"- Type: {content_type}")
            
            lines.append(f"- Size: {safe_format_file_size(size)}")
            
            if file_hash != "N/A":
                lines.append(f"- SHA256: {file_hash}")
            
            # Simplified VirusTotal results
            if vt_verdict == 'malicious':
                lines.append(f"- VirusTotal: MALICIOUS ({vt_comment})")
            elif vt_verdict == 'suspicious':
                lines.append(f"- VirusTotal: SUSPICIOUS ({vt_comment})")
            elif vt_verdict == 'benign':
                lines.append(f"- VirusTotal: Benign")
            else:
                lines.append(f"- VirusTotal: [Analyst to verify]")
            
            lines.append("")
            
            # Content analysis details (simplified)
            content_analysis = att.get('attachment_content_analysis')
            if content_analysis and content_analysis.get('analyzed'):
                text_length = content_analysis.get('text_length', 0)
                findings = content_analysis.get('findings', {})
                url_analysis = content_analysis.get('url_analysis', {})
                
                if findings:
                    lines.append("- Phishing content patterns detected:")
                    for finding_key, finding_data in findings.items():
                        if isinstance(finding_data, dict):
                            name = finding_data.get('name', 'Unknown')
                            count = finding_data.get('keyword_count', 0)
                            risk_level = finding_data.get('risk_level', 'UNKNOWN')
                            lines.append(f"  - {name} ({risk_level}): {count} indicators")
                
                if url_analysis and url_analysis.get('results'):
                    malicious_count = url_analysis.get('malicious_count', 0)
                    
                    if malicious_count > 0:
                        lines.append(f"- MALICIOUS URLs found: {malicious_count} domain{'s' if malicious_count != 1 else ''}")
                        
                        # Show malicious URL details with proper defanging
                        for result in url_analysis['results']:
                            if result.get('verdict') == 'malicious':
                                domain = result.get('domain', 'unknown')
                                display_domain = safe_defang_for_report(domain, output_mode)
                                lines.append(f"  - {display_domain}")
                
                lines.append("")
            
            # QR Code analysis details
            qr_analysis = att.get('qr_analysis')
            if qr_analysis and qr_analysis.get('qr_found'):
                lines.append("QR CODE ANALYSIS:")
                qr_results = qr_analysis.get('qr_results', [])
                
                for j, qr in enumerate(qr_results, 1):
                    if 'url' in qr:
                        # URL QR code
                        url = qr['url']
                        verdict = qr['verdict']
                        comment = qr['comment']
                        page = qr.get('page', 1)
                        
                        # Apply defanging to QR code URLs
                        display_url = safe_defang_for_report(url, output_mode)
                        
                        if page > 1:
                            lines.append(f"QR Code {j} (Page {page}):")
                        else:
                            lines.append(f"QR Code {j}:")
                        
                        lines.append(f"  Destination URL: {display_url}")
                        
                        if verdict == 'malicious':
                            lines.append(f"  Threat Assessment: MALICIOUS - {comment}")
                        elif verdict == 'suspicious':
                            lines.append(f"  Threat Assessment: SUSPICIOUS - {comment}")
                        elif verdict == 'benign':
                            lines.append(f"  Threat Assessment: Benign")
                        else:
                            lines.append(f"  Threat Assessment: [Analyst to verify]")
                    else:
                        # Non-URL QR code
                        data = qr.get('data', '')
                        page = qr.get('page', 1)
                        
                        if page > 1:
                            lines.append(f"QR Code {j} (Page {page}):")
                        else:
                            lines.append(f"QR Code {j}:")
                        
                        lines.append(f"  Content: {data[:100]}{'...' if len(data) > 100 else ''}")
                
                lines.append("")
            
            # Extension spoofing warnings
            if is_spoofed:
                lines.append("SPOOFING DETECTED:")
                lines.append(f"- {spoof_description}")
                if threat_level == 'critical':
                    lines.append("- CRITICAL THREAT: Malicious file disguised as document")
                elif threat_level == 'high':
                    lines.append("- HIGH RISK: File type mismatch indicates deception")
                lines.append("")
            
            # Risk assessment (simplified)
            final_risk_level = att.get('final_risk_level', 'unknown')
        
        return lines
    
    except Exception as e:
        return [f"Error formatting attachment analysis: {e}", ""]

def generate_unique_filename(base_path, filename):
    """Generate unique filename by adding (1), (2), etc. if file exists."""
    file_path = os.path.join(base_path, filename)
    
    if not os.path.exists(file_path):
        return file_path
    
    # Split filename and extension
    name_part, ext_part = os.path.splitext(filename)
    
    counter = 1
    while True:
        new_filename = f"{name_part} ({counter}){ext_part}"
        new_file_path = os.path.join(base_path, new_filename)
        
        if not os.path.exists(new_file_path):
            return new_file_path
        
        counter += 1
        if counter > 999:  # Prevent infinite loop
            break
    
    # Fallback with timestamp if we somehow hit 999 files
    timestamp = datetime.now().strftime("%H%M%S")
    fallback_filename = f"{name_part}_{timestamp}{ext_part}"
    return os.path.join(base_path, fallback_filename)

def generate_plaintext_report(analysis_results, output_mode="fanged"):
    """Generate customer-ready plaintext report."""
    try:
        # Generate filename in mm.dd.yyyy format only
        current_date = datetime.now().strftime("%m.%d.%Y")
        filename = f"email_analysis_{current_date}.txt"
        desktop_path = get_desktop_path()
        
        # Use the unique filename generator
        file_path = generate_unique_filename(desktop_path, filename)
        
        # Build report content
        report_lines = []
        
        # File information section
        file_info = analysis_results.get('file_info', {})
        if file_info:
            filename_info = file_info.get('filename', 'Unknown')
            file_type = file_info.get('file_type', 'Unknown')  
            file_size = file_info.get('file_size', 0)
            file_hash = file_info.get('file_hash', 'N/A')
            
            report_lines.append(format_section_header("EMAIL FILE INFORMATION"))
            report_lines.append("")
            report_lines.append(f"Filename: {filename_info}")
            report_lines.append(f"File Type: {file_type}")
            report_lines.append(f"File Size: {safe_format_file_size(file_size)}")
            if file_hash != "N/A":
                report_lines.append(f"SHA256 Hash: {file_hash}")
        
        # Final Verdict - Template for analyst to fill out
        report_lines.append("")
        report_lines.append("")
        report_lines.append(format_section_header("FINAL VERDICT"))
        report_lines.append("")
        report_lines.append("Classification: [Analyst to complete]")
        report_lines.append("")
        report_lines.append("Supporting Analysis:")
        report_lines.append("- [Analyst to complete based on findings below]")
        
        # Add all analysis sections
        report_lines.extend(format_header_analysis_section(analysis_results, output_mode))
        report_lines.extend(format_ip_analysis_section(analysis_results, output_mode))
        report_lines.extend(format_url_analysis_section(analysis_results, output_mode))
        report_lines.extend(format_body_analysis_section(analysis_results))
        report_lines.extend(format_attachment_analysis_section(analysis_results, output_mode))
        
        # Write report to file
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(report_lines))
        except PermissionError:
            # Try alternative location if desktop is not writable
            import tempfile
            temp_dir = tempfile.gettempdir()
            alt_file_path = os.path.join(temp_dir, os.path.basename(file_path))
            with open(alt_file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(report_lines))
            file_path = alt_file_path
        
        return file_path
        
    except Exception as e:
        raise Exception(f"Failed to generate report: {e}")

def collect_analysis_results():
    """Collect all analysis results from global variables in the main module."""
    try:
        import sys
        
        # Get the main module
        main_module = sys.modules.get('__main__') or sys.modules.get('phishalyzer')
        if not main_module:
            raise Exception("Could not access main phishalyzer module")
        
        # Collect all global analysis results
        analysis_results = {
            'file_info': {},
            'url_analysis': getattr(main_module, 'last_url_analysis_results', None),
            'ip_analysis': getattr(main_module, 'last_ip_analysis_results', None),
            'body_analysis': getattr(main_module, 'last_body_analysis_results', None),
            'attachment_analysis': getattr(main_module, 'last_attachment_results', None),
            'routing_hops': getattr(main_module, 'last_received_hops', None),
            'header_analysis': getattr(main_module, 'last_header_analysis', None)
        }
        
        # Collect file information
        file_path = getattr(main_module, 'last_analyzed_file_path', None)
        file_type = getattr(main_module, 'last_analyzed_file_type', None)
        
        if file_path:
            try:
                file_size = os.path.getsize(file_path)
                file_hash = calculate_file_hash(file_path)
                filename = os.path.basename(file_path)
                
                analysis_results['file_info'] = {
                    'filename': filename,
                    'file_path': file_path,
                    'file_type': file_type or 'Unknown',
                    'file_size': file_size,
                    'file_hash': file_hash
                }
            except Exception as e:
                analysis_results['file_info'] = {
                    'filename': os.path.basename(file_path) if file_path else 'Unknown',
                    'file_path': file_path or 'Unknown',
                    'file_type': file_type or 'Unknown',
                    'file_size': 0,
                    'file_hash': f'Error: {e}'
                }
        
        return analysis_results
        
    except Exception as e:
        raise Exception(f"Failed to collect analysis results: {e}")