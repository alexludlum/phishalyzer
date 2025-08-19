"""
Complete Terminal Output Capture HTML Export module for phishalyzer.
Captures ALL analysis data and converts it to HTML with exact terminal formatting.
"""

import os
import re
import hashlib
import datetime
import io
import sys
from pathlib import Path

# Import compatible output system
try:
    from .compatible_output import output, print_status
    COMPATIBLE_OUTPUT = True
except ImportError:
    COMPATIBLE_OUTPUT = False

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

def apply_defanging_to_output(text, use_defanged):
    """Apply defanging to terminal output based on export choice (independent of global settings)."""
    if not use_defanged or not text:
        return text
        
    try:
        result = str(text)
        
        # Check if content is already defanged (avoid double-defanging)
        if '[.]' in result or '[:]' in result:
            # Already defanged, return as-is
            return result
        
        # Use our own defanging logic independent of global settings
        
        # Replace protocols
        result = result.replace('https://', 'https[:]//') 
        result = result.replace('http://', 'http[:]//') 
        result = result.replace('ftp://', 'ftp[:]//') 
        
        # Replace common TLDs and domains
        replacements = [
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
            ('.cc', '[.]cc')
        ]
        
        for original, replacement in replacements:
            result = result.replace(original, replacement)
        
        # Handle IP addresses
        import re
        
        # IPv4 defanging
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        def defang_ipv4(match):
            return match.group(0).replace('.', '[.]')
        result = re.sub(ipv4_pattern, defang_ipv4, result)
        
        # IPv6 defanging (enhanced pattern to capture complete addresses)
        ipv6_patterns = [
            # Link-local addresses with full format (fe80::xxxx:xxxx:xxxx:xxxx with optional zone)
            r'\bfe80::[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}(?:%\d+)?\b',
            # Standard IPv6 with :: compression - comprehensive patterns
            r'\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,6}::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*\b',
            r'\b[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,6}\b',
            r'\b::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,7}\b',
            r'\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,6}::\b',
            # Full IPv6 without compression (8 groups)
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            # Partial matches for any remaining IPv6-like patterns
            r'\b[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}\b'
        ]
        
        def defang_ipv6(match):
            return match.group(0).replace(':', '[:]')
        
        for pattern in ipv6_patterns:
            result = re.sub(pattern, defang_ipv6, result)
        
        return result
    except Exception:
        return str(text)

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

def ansi_to_html_careful(text):
    """Convert ANSI escape sequences to HTML with careful handling to prevent issues."""
    # ANSI color code mappings to exact terminal colors
    ansi_colors = {
        # Regular colors
        '30': '#000000',  # Black
        '31': '#cd3131',  # Red
        '32': '#0dbc79',  # Green
        '33': '#e5e510',  # Yellow
        '34': '#2472c8',  # Blue
        '35': '#bc3fbc',  # Magenta
        '36': '#11a8cd',  # Cyan
        '37': '#e5e5e5',  # White
        
        # Bright colors
        '90': '#666666',  # Bright Black
        '91': '#f14c4c',  # Bright Red
        '92': '#23d18b',  # Bright Green
        '93': '#f5f543',  # Bright Yellow
        '94': '#3b8eea',  # Bright Blue
        '95': '#d670d6',  # Bright Magenta
        '96': '#29b8db',  # Bright Cyan
        '97': '#ffffff',  # Bright White
    }
    
    # Process ANSI escape sequences more carefully
    def replace_ansi_safe(match):
        full_match = match.group(0)
        codes = match.group(1)
        
        if not codes:
            return '</span>'
        
        code_list = codes.split(';')
        styles = []
        
        for code in code_list:
            code = code.strip()
            if code == '0' or code == '':  # Reset
                return '</span>'
            elif code == '1':  # Bold
                styles.append('font-weight: bold')
            elif code in ansi_colors:
                styles.append(f'color: {ansi_colors[code]}')
        
        if styles:
            return f'<span style="{"; ".join(styles)}">'
        return ''
    
    # FIXED: Preserve defanged brackets during HTML escaping
    # Temporarily replace defanged brackets with placeholders
    text = text.replace('[.]', '|||DOT|||')
    text = text.replace('[:]', '|||COLON|||')
    
    # First, escape HTML characters
    html_text = escape_html(text)
    
    # Restore defanged brackets AFTER HTML escaping
    html_text = html_text.replace('|||DOT|||', '[.]')
    html_text = html_text.replace('|||COLON|||', '[:]')
    
    # Then convert ANSI codes
    ansi_pattern = re.compile(r'\033\[([0-9;]*)m')
    html_text = ansi_pattern.sub(replace_ansi_safe, html_text)
    
    # Close any remaining open spans at line breaks to prevent bleeding
    lines = html_text.split('\n')
    processed_lines = []
    
    for line in lines:
        # Count open and close spans in this line
        open_spans = line.count('<span')
        close_spans = line.count('</span>')
        
        # If there are unmatched open spans, close them at the end of the line
        if open_spans > close_spans:
            line += '</span>' * (open_spans - close_spans)
        
        processed_lines.append(line)
    
    # Rejoin with newlines
    html_text = '\n'.join(processed_lines)
    
    return html_text

def capture_complete_analysis_data(file_path, file_type, use_defanged):
    """Capture ALL analysis data including detailed breakdowns using the same API key."""
    
    import sys
    import io
    import os
    
    try:
        # Import analysis modules
        from . import parser
        from . import header_analyzer
        from . import ioc_extractor
        from . import url_extractor
        from . import body_analyzer
        from . import attachment_analyzer
        
        # DIRECT MODULE OVERRIDE - More reliable than file manipulation
        original_output_mode = None
        main_module = sys.modules.get('__main__') or sys.modules.get('phishalyzer')
        
        if use_defanged and main_module:
            # Save original output mode from main module
            original_output_mode = getattr(main_module, 'output_mode', 'fanged')
            # Temporarily override the global output_mode variable
            setattr(main_module, 'output_mode', 'defanged')
        
        # ALSO override the file-based check for url_extractor
        OUTPUT_MODE_FILE = os.path.expanduser("~/.phishalyzer_output_mode")
        original_file_mode = None
        
        if use_defanged:
            # Save original file mode
            try:
                if os.path.exists(OUTPUT_MODE_FILE):
                    with open(OUTPUT_MODE_FILE, "r", encoding='utf-8') as f:
                        original_file_mode = f.read().strip()
                else:
                    original_file_mode = None  # File didn't exist
                
                # Temporarily set to defanged
                with open(OUTPUT_MODE_FILE, "w", encoding='utf-8') as f:
                    f.write("defanged")
            except Exception:
                pass
        
        try:
            # Get the API key from the main module
            api_key = None
            if main_module:
                # Try to get the saved API key the same way the main script does
                try:
                    api_key = getattr(main_module, 'get_saved_api_key', lambda: None)()
                except:
                    pass
            
            # Load the email
            msg_obj, _ = parser.load_email(file_path)
            
            # Store all analysis results
            analysis_data = {}
            
            # Helper function to capture output and store results
            def capture_with_data(func, *args, **kwargs):
                old_stdout = sys.stdout
                old_input = __builtins__['input'] if 'input' in __builtins__ else input
                sys.stdout = captured_output = io.StringIO()
                
                # Override input function to auto-skip rate limit prompts
                def mock_input(prompt=""):
                    if "rate limit" in prompt.lower() or "wait" in prompt.lower() or "skip" in prompt.lower():
                        return "skip"  # Always skip rate limit prompts during export
                    return "skip"  # Default to skip for any input during export
                
                __builtins__['input'] = mock_input
                
                try:
                    result = func(*args, **kwargs)
                    output_text = captured_output.getvalue()
                    
                    # FIXED: Only apply defanging if user chose defanged export
                    if use_defanged:
                        output_text = apply_defanging_to_output(output_text, True)
                    
                    return output_text, result
                except Exception as e:
                    return f"Error capturing output: {e}", None
                finally:
                    sys.stdout = old_stdout
                    __builtins__['input'] = old_input
            
            # 1. Header Analysis (including detailed factors)
            try:
                header_output, _ = capture_with_data(header_analyzer.analyze_headers, msg_obj)
                analysis_data['header_analysis'] = header_output
                
                # Also get the stored hops data
                if main_module and hasattr(main_module, 'last_received_hops'):
                    analysis_data['received_hops'] = getattr(main_module, 'last_received_hops', [])
                else:
                    analysis_data['received_hops'] = []
                    
            except Exception as e:
                analysis_data['header_analysis'] = f"Error: {e}"
                analysis_data['received_hops'] = []
            
            # 2. IP Analysis (with API key)
            try:
                ip_output, ip_results = capture_with_data(ioc_extractor.analyze_ips, msg_obj, api_key)
                analysis_data['ip_analysis'] = ip_output
                analysis_data['ip_results'] = ip_results
            except Exception as e:
                analysis_data['ip_analysis'] = f"Error: {e}"
                analysis_data['ip_results'] = []
            
            # 3. URL Analysis (with API key and detailed breakdown)
            try:
                url_output, url_results = capture_with_data(url_extractor.analyze_urls, msg_obj, api_key)
                analysis_data['url_analysis'] = url_output
                analysis_data['url_results'] = url_results
            except Exception as e:
                analysis_data['url_analysis'] = f"Error: {e}"
                analysis_data['url_results'] = []
            
            # 4. Body Analysis (with detailed breakdown)
            try:
                body_output, body_results = capture_with_data(body_analyzer.analyze_email_body, msg_obj, api_key)
                analysis_data['body_analysis'] = body_output
                analysis_data['body_results'] = body_results
            except Exception as e:
                analysis_data['body_analysis'] = f"Error: {e}"
                analysis_data['body_results'] = None
            
            # 5. Attachment Analysis (with all details)
            try:
                attachment_output, attachment_results = capture_with_data(attachment_analyzer.analyze_attachments, msg_obj, api_key)
                analysis_data['attachment_analysis'] = attachment_output
                analysis_data['attachment_results'] = attachment_results
            except Exception as e:
                analysis_data['attachment_analysis'] = f"Error: {e}"
                analysis_data['attachment_results'] = []
            
            return analysis_data
            
        finally:
            # RESTORE both the module variable and file
            if use_defanged:
                # Restore main module output_mode
                if main_module and original_output_mode is not None:
                    setattr(main_module, 'output_mode', original_output_mode)
                
                # Restore file mode
                try:
                    if original_file_mode is None:
                        # File didn't exist originally, remove it
                        if os.path.exists(OUTPUT_MODE_FILE):
                            os.remove(OUTPUT_MODE_FILE)
                    elif original_file_mode == "fanged":
                        # Remove the file if it was originally fanged (default)
                        if os.path.exists(OUTPUT_MODE_FILE):
                            os.remove(OUTPUT_MODE_FILE)
                    else:
                        # Restore the original mode
                        with open(OUTPUT_MODE_FILE, "w", encoding='utf-8') as f:
                            f.write(original_file_mode)
                except Exception:
                    pass
        
    except Exception as e:
        return {'error': f"Failed to capture analysis data: {e}"}

def remove_menu_hints_from_output(text):
    """Remove menu hints from any analysis output."""
    if not text:
        return text
    
    lines = text.split('\n')
    filtered_lines = []
    
    for line in lines:
        line_clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
        
        # Skip menu hints
        if ("Use menu option" in line_clean and "for full details" in line_clean) or \
           ("Use menu option" in line_clean and "for full breakdown" in line_clean):
            continue
            
        filtered_lines.append(line)
    
    return "\n".join(filtered_lines)

def extract_header_factors_and_assessment(header_output):
    """Extract warning/benign factors and header assessment from header analysis output."""
    if not header_output:
        return "", ""
    
    lines = header_output.split('\n')
    warning_factors = []
    benign_factors = []
    malicious_factors = []
    assessment_line = ""
    
    current_section = None
    
    for line in lines:
        line_clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
        
        if line_clean.startswith("Malicious factors:"):
            current_section = "malicious"
            continue
        elif line_clean.startswith("Warning factors:"):
            current_section = "warning"
            continue
        elif line_clean.startswith("Benign factors:"):
            current_section = "benign"
            continue
        elif line_clean.startswith("HEADER ASSESSMENT:"):
            assessment_line = line  # Keep the full ANSI-formatted line
            break
        
        if current_section and line_clean.startswith("- "):
            factor = line_clean[2:]  # Remove "- "
            if current_section == "warning":
                warning_factors.append(factor)
            elif current_section == "benign":
                benign_factors.append(factor)
            elif current_section == "malicious":
                malicious_factors.append(factor)
    
    # Format the factors with proper coloring
    factors_output = []
    
    if malicious_factors:
        factors_output.append("\033[31mMalicious factors:\033[0m")
        for factor in malicious_factors:
            factors_output.append(f"- {factor}")
        factors_output.append("")
    
    if warning_factors:
        factors_output.append("\033[93mWarning factors:\033[0m")
        for factor in warning_factors:
            factors_output.append(f"- {factor}")
        factors_output.append("")
    
    if benign_factors:
        factors_output.append("\033[32mBenign factors:\033[0m")
        for factor in benign_factors:
            factors_output.append(f"- {factor}")
        factors_output.append("")
    
    return "\n".join(factors_output), assessment_line

def generate_enhanced_url_analysis(url_output, url_results, use_defanged=True):
    """Generate enhanced URL analysis that matches the terminal output format."""
    if not url_results:
        return url_output
    
    # Remove the existing summary and menu hints from url_output
    lines = url_output.split('\n')
    clean_lines = []
    
    for line in lines:
        line_clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
        
        # Keep the "Found X URLs across Y domains" line
        if line_clean.startswith("Found") and "URLs across" in line_clean:
            clean_lines.append(line)
            clean_lines.append("")  # Add blank line after summary
            break
    
    # Now build the detailed breakdown in the same format as the terminal
    enhanced_lines = clean_lines.copy()
    
    # Group by verdict for detailed display
    malicious_domains = [r for r in url_results if r['verdict'] == 'malicious']
    suspicious_domains = [r for r in url_results if r['verdict'] == 'suspicious']
    benign_domains = [r for r in url_results if r['verdict'] == 'benign']
    unchecked_domains = [r for r in url_results if r['verdict'] == 'unchecked']
    
    # Display each category in order: MALICIOUS, SUSPICIOUS, UNCHECKED, BENIGN
    for category_name, domains, color_code in [
        ("MALICIOUS", malicious_domains, "31"),  # Red
        ("SUSPICIOUS", suspicious_domains, "93"), # Orange/Yellow
        ("UNCHECKED", unchecked_domains, "93"),   # Orange/Yellow
        ("BENIGN", benign_domains, "32")          # Green
    ]:
        if not domains:
            continue
        
        domain_count = len(domains)
        
        # Add category header
        enhanced_lines.append(f"\033[{color_code}m{category_name} DOMAINS ({domain_count}):\033[0m")
        
        for result in domains:
            domain = result['domain']
            url_count = result['url_count']
            comment = result['comment']
            representative_url = result.get('representative_url', '')
            
            # FIXED: Apply defanging only if requested for export
            display_domain = apply_defanging_to_output(domain, use_defanged) if use_defanged and '[.]' not in domain else domain
            display_representative = apply_defanging_to_output(representative_url, use_defanged) if use_defanged and representative_url and '[.]' not in representative_url and '[:]' not in representative_url else representative_url
            
            # Format domain line
            enhanced_lines.append(f"- {display_domain} ({url_count} URL{'s' if url_count != 1 else ''}) - {comment}")
            
            # Add sample URL if available
            if display_representative:
                enhanced_lines.append(f"  Sample: {display_representative}")
        
        enhanced_lines.append("")  # Blank line after each category
    
    return "\n".join(enhanced_lines)

def generate_detailed_url_breakdown(url_results, use_defanged=True):
    """Generate the additional detailed URL breakdown for domains with multiple URLs."""
    if not url_results:
        return ""
    
    breakdown_lines = []
    
    # Group by verdict for detailed display
    malicious_domains = [r for r in url_results if r['verdict'] == 'malicious']
    suspicious_domains = [r for r in url_results if r['verdict'] == 'suspicious']
    benign_domains = [r for r in url_results if r['verdict'] == 'benign']
    unchecked_domains = [r for r in url_results if r['verdict'] == 'unchecked']
    
    # Show detailed breakdown for each category if there are multiple URLs
    for category_name, domains, color in [
        ("MALICIOUS", malicious_domains, "red"),
        ("SUSPICIOUS", suspicious_domains, "orange3"),
        ("UNCHECKED", unchecked_domains, "orange3"),
        ("BENIGN", benign_domains, "green")
    ]:
        if not domains:
            continue
            
        # Check if any domain has multiple URLs
        has_multiple_urls = any(len(d['urls']) > 1 for d in domains)
        
        if has_multiple_urls:
            breakdown_lines.append("")  # Spacing
            breakdown_lines.append(f"\033[{'31' if color == 'red' else '93' if color == 'orange3' else '32' if color == 'green' else '33'}mDetailed {category_name} URL Breakdown:\033[0m")
            
            for result in domains:
                if len(result['urls']) > 1:
                    domain = result['domain']
                    urls = result['urls']
                    
                    # FIXED: Apply defanging only if requested for export
                    display_domain = apply_defanging_to_output(domain, use_defanged) if use_defanged and '[.]' not in domain else domain
                    display_urls = []
                    for url in urls:
                        if use_defanged and '[.]' not in url and '[:]' not in url:
                            display_urls.append(apply_defanging_to_output(url, True))
                        else:
                            display_urls.append(url)
                    
                    breakdown_lines.append(f"  {display_domain} ({len(urls)} URLs):")
                    for i, url in enumerate(display_urls, 1):
                        breakdown_lines.append(f"    {i:2}. {url}")
    
    # Add final blank line if we generated any breakdown content
    if breakdown_lines:
        breakdown_lines.append("")
    
    return "\n".join(breakdown_lines)

def generate_detailed_body_breakdown(body_results):
    """Generate detailed body analysis breakdown for integration."""
    if not body_results or not body_results.get("findings"):
        return ""
    
    breakdown_lines = []
    findings = body_results["findings"]
    
    if findings:
        breakdown_lines.append("")  # Spacing
        breakdown_lines.append("\033[34mDetailed Body Analysis Breakdown:\033[0m")
        
        # Sort findings by risk level
        risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_findings = sorted(findings.values(), key=lambda x: (risk_order.get(x["risk_level"], 3), x["name"]))
        
        for finding in sorted_findings:
            risk_level = finding["risk_level"]
            name = finding["name"]
            description = finding["description"]
            matched_keywords = finding["matched_keywords"]
            
            # Determine color for risk level
            if risk_level == "HIGH":
                risk_color = "31"  # Red
            elif risk_level == "MEDIUM":
                risk_color = "93"  # Orange
            else:
                risk_color = "33"  # Yellow
            
            # Display category header
            breakdown_lines.append(f"  \033[{risk_color}m[{risk_level}] {name}:\033[0m")
            breakdown_lines.append(f"    Description: {description}")
            
            # Display matched keywords
            breakdown_lines.append("    Matched keywords:")
            for match in matched_keywords:
                keyword = match["keyword"]
                matched_text = match["matched_text"]
                exact_match = match["exact_match"]
                
                if exact_match:
                    match_info = "exact match"
                else:
                    match_info = f'found: "{matched_text}"'
                
                breakdown_lines.append(f"    - \"{keyword}\" ({match_info})")
            
            breakdown_lines.append("")  # Blank line between categories
    
    return "\n".join(breakdown_lines)

def remove_header_factors_and_menu_hints(header_output):
    """Remove factors section and menu hints from header output."""
    if not header_output:
        return header_output
    
    lines = header_output.split('\n')
    filtered_lines = []
    skip_section = False
    
    for line in lines:
        line_clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
        
        # Skip factors sections
        if line_clean.startswith(("Malicious factors:", "Warning factors:", "Benign factors:")):
            skip_section = True
            continue
        elif line_clean.startswith("HEADER ASSESSMENT:"):
            skip_section = False
            continue  # Skip the header assessment line - we'll add it back later
        
        # Skip menu hints
        if "Use menu option" in line_clean and "for full details" in line_clean:
            continue
        if "Use menu option" in line_clean and "for full breakdown" in line_clean:
            continue
            
        if not skip_section:
            filtered_lines.append(line)
        elif skip_section and line_clean and not line_clean.startswith("- "):
            # End of factors section
            skip_section = False
            filtered_lines.append(line)
    
    return "\n".join(filtered_lines)

def generate_comprehensive_html_report(file_path, file_type, use_defanged):
    """Generate comprehensive HTML report with all analysis data."""
    
    # Calculate file details
    email_filename = os.path.basename(file_path)
    file_size = get_file_size(file_path)
    file_hash = calculate_file_hash(file_path)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Capture all analysis data
    analysis_data = capture_complete_analysis_data(file_path, file_type, use_defanged)
    
    if 'error' in analysis_data:
        # Handle error case
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishalyzer Analysis Report - Error</title>
    <style>
        body {{ background-color: #0c0c0c; color: #cccccc; font-family: 'Courier New', monospace; }}
    </style>
</head>
<body>
    <div style="padding: 20px;">
        <h1>Analysis Error</h1>
        <p>{escape_html(analysis_data['error'])}</p>
    </div>
</body>
</html>"""
        return html_content
    
    # Build HTML with exact terminal styling and FIXED spacing
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
        
        .report-header {{
            color: #cccccc;
            font-weight: bold;
            border-bottom: 1px solid #333333;
            padding-bottom: 20px;
            margin-bottom: 20px;
        }}
        
        .section-header {{
            color: #bc3fbc;
            font-weight: bold;
            margin: 15px 0 15px 0;
        }}
        
        a {{ color: #3b8eea; }}
    </style>
</head>
<body>
    <div class="terminal-container">
        <div class="report-header"><span style="color: #2472c8;">EMAIL ANALYSIS REPORT</span>

<span style="color: #2472c8;">Generated:</span> {timestamp}
<span style="color: #2472c8;">File:</span> {escape_html(email_filename)}
<span style="color: #2472c8;">Size:</span> {file_size}
<span style="color: #2472c8;">Type:</span> {file_type.upper()}
<span style="color: #2472c8;">SHA256:</span> {file_hash}
<span style="color: #2472c8;">Output:</span> {'Defanged' if use_defanged else 'Fanged'}</div>
"""

    # EMAIL HEADER ANALYSIS Section
    header_output = analysis_data.get('header_analysis', '')
    received_hops = analysis_data.get('received_hops', [])
    
    if header_output:
        # Remove factors and menu hints from header output (we'll add them later)
        clean_header_output = remove_header_factors_and_menu_hints(header_output)
        
        # Extract factors and assessment
        factors_output, assessment_line = extract_header_factors_and_assessment(header_output)
        
        # Add section header
        html_content += '<div class="section-header">============================ EMAIL HEADER ANALYSIS ============================</div>\n'
        
        # Add the cleaned header analysis
        if clean_header_output.strip():
            html_content += ansi_to_html_careful(clean_header_output)
        
        # Add detailed received hops if available (without the header)
        if received_hops:
            for hop in received_hops:
                index = hop.get('index', '?')
                content = hop.get('content', 'No content')
                
                # The content already has ANSI codes - convert carefully
                hop_display = f"<span style=\"color: #2472c8;\">[{index}]</span> {ansi_to_html_careful(content)}\n"
                html_content += hop_display
        
        # Add the extracted factors before the header assessment
        if factors_output.strip():
            html_content += '\n\n' + ansi_to_html_careful(factors_output)
        
        # Add the header assessment at the end
        if assessment_line.strip():
            html_content += '\n' + ansi_to_html_careful(assessment_line)
            # Add blank line after header assessment
            html_content += '\n'

    # IP ADDRESS ANALYSIS Section
    ip_output = analysis_data.get('ip_analysis', '')
    if ip_output and ip_output.strip():
        clean_ip_output = remove_menu_hints_from_output(ip_output)
        html_content += '\n<div class="section-header">============================= IP ADDRESS ANALYSIS =============================</div>\n'
        html_content += ansi_to_html_careful(clean_ip_output)

    # URL ANALYSIS Section  
    url_output = analysis_data.get('url_analysis', '')
    url_results = analysis_data.get('url_results', [])
    
    if url_output and url_output.strip():
        # Generate enhanced URL analysis that matches the terminal format
        enhanced_url_output = generate_enhanced_url_analysis(url_output, url_results, use_defanged)
        
        html_content += '\n<div class="section-header">================================ URL ANALYSIS ================================</div>\n'
        html_content += ansi_to_html_careful(enhanced_url_output)
        
        # Add additional detailed URL breakdown for domains with multiple URLs
        detailed_breakdown = generate_detailed_url_breakdown(url_results, use_defanged)
        if detailed_breakdown.strip():
            html_content += '\n' + ansi_to_html_careful(detailed_breakdown)
            # Add extra spacing after detailed breakdown to match terminal output
            html_content += '\n'

    # EMAIL BODY ANALYSIS Section
    body_output = analysis_data.get('body_analysis', '')
    body_results = analysis_data.get('body_results')
    
    if body_output and body_output.strip():
        clean_body_output = remove_menu_hints_from_output(body_output)
        html_content += '\n<div class="section-header">============================== EMAIL BODY ANALYSIS ==============================</div>\n'
        html_content += ansi_to_html_careful(clean_body_output)
        
        # Add detailed body breakdown
        detailed_breakdown = generate_detailed_body_breakdown(body_results)
        if detailed_breakdown.strip():
            html_content += '\n' + ansi_to_html_careful(detailed_breakdown)

    # ATTACHMENT ANALYSIS Section
    attachment_output = analysis_data.get('attachment_analysis', '')
    if attachment_output and attachment_output.strip():
        clean_attachment_output = remove_menu_hints_from_output(attachment_output)
        html_content += '\n<div class="section-header">============================= ATTACHMENT ANALYSIS =============================</div>\n'
        html_content += ansi_to_html_careful(clean_attachment_output)

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
                output.print("[blue]1:[/blue] Complete Terminal Report (HTML)")
                output.print("[blue]2:[/blue] Markdown Report (coming soon)")
                output.print("[blue]3:[/blue] Plaintext Report (coming soon)")
                output.print("[blue]4:[/blue] Return to main menu")
            else:
                print("\nExport Format:")
                print("1: Complete Terminal Report (HTML)")
                print("2: Markdown Report (coming soon)")
                print("3: Plaintext Report (coming soon)")
                print("4: Return to main menu")
            
            try:
                choice = input("Enter option [1-4]: ").strip()
                if choice in ['1']:
                    format_type = 'complete-html'
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
    """Main function to export comprehensive analysis report."""
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
        if format_type == 'complete-html':
            if COMPATIBLE_OUTPUT:
                print_status("Generating comprehensive analysis report...", "info")
            else:
                print("Generating comprehensive analysis report...")
            
            html_content = generate_comprehensive_html_report(file_path, file_type, use_defanged)
            
            # Generate filename
            email_filename = os.path.basename(file_path)
            sanitized_name = sanitize_filename(email_filename)
            timestamp = datetime.datetime.now().strftime("%Y.%m.%d")
            base_filename = f"{sanitized_name}_complete_report_{timestamp}"
            
            # Get desktop path and create unique filename
            desktop_path = get_desktop_path()
            output_path = get_unique_filename(desktop_path, base_filename, 'html')
            
            # Write file
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                if COMPATIBLE_OUTPUT:
                    print_status(f"Complete analysis report saved successfully!", "success")
                    output.print(f"[blue]File location:[/blue] {output_path}")
                    
                    # Show file size
                    file_size = os.path.getsize(output_path)
                    if file_size >= 1024:
                        size_str = f"{file_size / 1024:.1f} KB"
                    else:
                        size_str = f"{file_size} B"
                    output.print(f"[blue]File size:[/blue] {size_str}")
                else:
                    print(f"Complete analysis report saved successfully!")
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
            print_status(f"Error generating comprehensive analysis report: {e}", "error")
        else:
            print(f"Error generating comprehensive analysis report: {e}")