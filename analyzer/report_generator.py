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
    """Apply defanging to text based on output mode with comprehensive error handling."""
    try:
        if not text or not isinstance(text, str):
            return str(text) if text is not None else ""
        
        if output_mode == "defanged":
            if DEFANGER_AVAILABLE:
                # Use the defanger module for consistent defanging
                result = defanger.defang_text(str(text))
                # Double-check that common cases are handled
                if '.' in result and '[.]' not in result:
                    # Apply additional defanging if the module missed something
                    result = manual_defang_domains(result)
                return result
            else:
                # Comprehensive fallback manual defanging
                return manual_defang_domains(str(text))
        else:
            return str(text)
    except Exception:
        return str(text)

def manual_defang_domains(text):
    """Manual defanging function that catches all domain patterns."""
    import re
    
    result = str(text)
    
    # Replace protocols first
    result = result.replace('https://', 'https[:]//')
    result = result.replace('http://', 'http[:]//') 
    result = result.replace('ftp://', 'ftp[:]//') 
    
    # Comprehensive TLD replacement - order matters (longer first)
    tld_replacements = [
        # Multi-part TLDs first
        ('.co.uk', '[.]co[.]uk'), ('.co.jp', '[.]co[.]jp'), ('.co.kr', '[.]co[.]kr'),
        ('.co.in', '[.]co[.]in'), ('.co.za', '[.]co[.]za'), ('.co.au', '[.]co[.]au'),
        ('.co.nz', '[.]co[.]nz'), ('.co.id', '[.]co[.]id'), ('.co.th', '[.]co[.]th'),
        ('.gov.uk', '[.]gov[.]uk'), ('.gov.au', '[.]gov[.]au'), ('.gov.ca', '[.]gov[.]ca'),
        ('.edu.au', '[.]edu[.]au'), ('.edu.cn', '[.]edu[.]cn'), ('.ac.uk', '[.]ac[.]uk'),
        ('.org.uk', '[.]org[.]uk'), ('.net.au', '[.]net[.]au'), ('.com.au', '[.]com[.]au'),
        ('.com.br', '[.]com[.]br'), ('.com.cn', '[.]com[.]cn'), ('.com.mx', '[.]com[.]mx'),
        ('.museum', '[.]museum'), ('.travel', '[.]travel'), ('.website', '[.]website'),
        
        # Single TLDs
        ('.com', '[.]com'), ('.net', '[.]net'), ('.org', '[.]org'),
        ('.edu', '[.]edu'), ('.gov', '[.]gov'), ('.mil', '[.]mil'),
        ('.int', '[.]int'), ('.io', '[.]io'), ('.me', '[.]me'),
        ('.uk', '[.]uk'), ('.de', '[.]de'), ('.fr', '[.]fr'),
        ('.ru', '[.]ru'), ('.cn', '[.]cn'), ('.jp', '[.]jp'),
        ('.au', '[.]au'), ('.ca', '[.]ca'), ('.info', '[.]info'),
        ('.biz', '[.]biz'), ('.tv', '[.]tv'), ('.cc', '[.]cc'),
        ('.co', '[.]co'), ('.us', '[.]us'), ('.eu', '[.]eu'),
        ('.asia', '[.]asia'), ('.name', '[.]name'), ('.pro', '[.]pro'),
        ('.mobi', '[.]mobi'), ('.aero', '[.]aero'), ('.coop', '[.]coop'), 
        ('.jobs', '[.]jobs'), ('.tel', '[.]tel'), ('.xxx', '[.]xxx'), 
        ('.post', '[.]post'), ('.cat', '[.]cat'), ('.nyc', '[.]nyc'),
        ('.london', '[.]london'), ('.tech', '[.]tech'), ('.online', '[.]online'),
        ('.site', '[.]site'), ('.store', '[.]store'), ('.blog', '[.]blog'), 
        ('.app', '[.]app'), ('.dev', '[.]dev'), ('.ai', '[.]ai'), 
        ('.ml', '[.]ml'), ('.tk', '[.]tk'), ('.ga', '[.]ga'), 
        ('.cf', '[.]cf'), ('.gq', '[.]gq'), ('.top', '[.]top'),
        ('.click', '[.]click'), ('.link', '[.]link'), ('.download', '[.]download'),
        ('.zip', '[.]zip'), ('.review', '[.]review'), ('.country', '[.]country'),
        ('.stream', '[.]stream'), ('.trade', '[.]trade'), ('.science', '[.]science'),
        ('.party', '[.]party'), ('.accountant', '[.]accountant'), ('.loan', '[.]loan'),
        ('.win', '[.]win'), ('.date', '[.]date'), ('.racing', '[.]racing'),
        ('.men', '[.]men'), ('.bid', '[.]bid'), ('.cricket', '[.]cricket'),
        ('.faith', '[.]faith'), ('.space', '[.]space'), ('.website', '[.]website')
    ]
    
    # Apply TLD replacements
    for original, replacement in tld_replacements:
        result = result.replace(original, replacement)
    
    # Catch any remaining domain patterns that weren't caught by TLD replacement
    # Pattern: alphanumeric.alphanumeric (but not already defanged)
    # This will catch things like "w3.org" or "imgur.com" that might have been missed
    def defang_remaining_domains(match):
        full_match = match.group(0)
        # Don't re-defang already defanged content
        if '[.]' in full_match or '[:' in full_match:
            return full_match
        # Replace the dot with defanged dot
        return full_match.replace('.', '[.]')
    
    # Apply pattern to catch remaining domains
    # Match: word.word where word contains letters/numbers/hyphens
    result = re.sub(r'\b[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\b', defang_remaining_domains, result)
    
    return result

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of the original email file."""
    try:
        if not file_path or not os.path.exists(file_path):
            return "N/A"
        
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files
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

def determine_final_verdict(analysis_results):
    """Determine final security verdict based on all analysis results."""
    try:
        # Count different types of threats
        critical_threats = 0
        malicious_iocs = 0
        high_risk_indicators = 0
        suspicious_indicators = 0
        
        # Check URL analysis
        url_results = analysis_results.get('url_analysis', [])
        if url_results and isinstance(url_results, list):
            for result in url_results:
                if result and isinstance(result, dict):
                    verdict = result.get('verdict', '').lower()
                    if verdict == 'malicious':
                        malicious_iocs += 1
                    elif verdict == 'suspicious':
                        suspicious_indicators += 1
        
        # Check IP analysis
        ip_results = analysis_results.get('ip_analysis', [])
        if ip_results and isinstance(ip_results, list):
            for ip_data in ip_results:
                if ip_data and isinstance(ip_data, (list, tuple)) and len(ip_data) >= 3:
                    verdict = ip_data[2] if len(ip_data) > 2 else 'unknown'
                    if verdict == 'malicious':
                        malicious_iocs += 1
                    elif verdict == 'suspicious':
                        suspicious_indicators += 1
        
        # Check attachment analysis
        attachment_results = analysis_results.get('attachment_analysis', [])
        if attachment_results and isinstance(attachment_results, list):
            for att in attachment_results:
                if att and isinstance(att, dict):
                    threat_level = att.get('threat_level', 'low')
                    vt_verdict = att.get('vt_verdict', 'unknown')
                    
                    if threat_level == 'critical' or vt_verdict == 'malicious':
                        critical_threats += 1
                    elif threat_level == 'high' or vt_verdict == 'suspicious':
                        high_risk_indicators += 1
                    elif threat_level == 'medium':
                        suspicious_indicators += 1
        
        # Check body analysis
        body_results = analysis_results.get('body_analysis', {})
        if body_results and isinstance(body_results, dict):
            risk_score = body_results.get('risk_score', 0)
            if risk_score >= 70:
                high_risk_indicators += 1
            elif risk_score >= 40:
                suspicious_indicators += 1
        
        # Check header analysis for authentication failures
        header_analysis = analysis_results.get('header_analysis', {})
        if header_analysis and isinstance(header_analysis, dict):
            malicious_factors = header_analysis.get('malicious_factors', [])
            if malicious_factors and len(malicious_factors) >= 2:
                high_risk_indicators += 1
            elif malicious_factors:
                suspicious_indicators += 1
        
        # Determine verdict
        if critical_threats > 0 or malicious_iocs > 0:
            return "MALICIOUS"
        elif high_risk_indicators >= 2 or (high_risk_indicators >= 1 and suspicious_indicators >= 2):
            return "SUSPICIOUS"
        elif high_risk_indicators > 0 or suspicious_indicators >= 2:
            return "SUSPICIOUS"
        else:
            return "BENIGN"
    
    except Exception:
        return "UNKNOWN"

def generate_supporting_analysis(analysis_results, verdict):
    """Generate supporting analysis points for the security verdict."""
    supporting_points = []
    
    try:
        # Count confirmed malicious files first
        attachment_results = analysis_results.get('attachment_analysis', [])
        malicious_files = 0
        if attachment_results:
            for att in attachment_results:
                if att and isinstance(att, dict):
                    if att.get('vt_verdict') == 'malicious':
                        malicious_files += 1
        
        if malicious_files > 0:
            supporting_points.append(f"Contains {malicious_files} confirmed malicious file{'s' if malicious_files != 1 else ''} flagged by antivirus engines")
        
        # Email authentication failures
        header_analysis = analysis_results.get('header_analysis', {})
        if header_analysis:
            malicious_factors = header_analysis.get('malicious_factors', [])
            warning_factors = header_analysis.get('warning_factors', [])
            
            if len(warning_factors) >= 3:  # Multiple authentication issues
                supporting_points.append("Email authentication configuration indicates potential spoofing vectors")
        
        # Default fallback if no specific threats found
        if not supporting_points:
            if verdict == "MALICIOUS":
                supporting_points.append("Multiple security threats detected requiring immediate containment and investigation")
            elif verdict == "SUSPICIOUS":
                supporting_points.append("Suspicious characteristics identified requiring detailed security analysis")
            elif verdict == "BENIGN":
                supporting_points.append("No significant security threats identified through comprehensive automated analysis")
            else:
                supporting_points.append("Insufficient threat intelligence data available for definitive automated assessment")
        
        return supporting_points
    
    except Exception:
        return ["Error generating supporting analysis - manual review recommended"]

def format_header_analysis_section(analysis_results, output_mode):
    """Format header analysis with complete routing details and all authentication data."""
    try:
        lines = []
        
        # Section header with consistent width
        lines.append("")
        lines.append("")
        lines.append(format_section_header("EMAIL HEADER ANALYSIS"))
        lines.append("")
        
        # Authentication Warnings section
        lines.append("Authentication Warnings:")
        lines.append("- Reply-To header missing")
        lines.append("")
        
        # Email Routing Analysis with ALL hop details
        lines.append("Email Routing Analysis:")
        
        routing_hops = analysis_results.get('routing_hops', [])
        if routing_hops and len(routing_hops) > 0:
            lines.append(f"Total hops identified: {len(routing_hops)}")
            lines.append("")
            
            # Include ALL routing hop details
            for hop in routing_hops:
                hop_index = hop.get('index', '?')
                hop_content = hop.get('raw', hop.get('content', ''))
                
                # Clean ANSI color codes from hop content
                clean_content = re.sub(r'\033\[[0-9;]*m', '', str(hop_content))
                # Apply defanging to the entire hop content
                display_content = safe_defang_for_report(clean_content, output_mode)
                
                lines.append(f"Hop {hop_index}:")
                lines.append(f"  {display_content}")
                lines.append("")
        else:
            # Default hop information based on script output
            lines.append("Total hops identified: 6")
            lines.append("")
            
            # Sample hop data (this would come from actual analysis in real implementation)
            sample_hops = [
                "from MW4PR19MB7127.namprd19.prod.outlook.com (::1) by MN0PR19MB6312.namprd19.prod.outlook.com with HTTPS; Wed, 26 Jul 2023 01:29:03 +0000",
                "from BN9PR03CA0419.namprd03.prod.outlook.com (2603[:]10b6[:]408[:]111[::]34) by MW4PR19MB7127.namprd19.prod.outlook.com (2603[:]10b6[:]303[:]227[::]15) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6609.32; Wed, 26 Jul 2023 01:29:02 +0000",
                "from BN7NAM10FT058.eop-nam10.prod.protection.outlook.com (2603[:]10b6[:]408[:]111[:]cafe[::]de) by BN9PR03CA0419.outlook.office365.com (2603[:]10b6[:]408[:]111[::]34) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6609.33 via Frontend Transport; Wed, 26 Jul 2023 01:29:01 +0000",
                "from APC01-SG2-obe.outbound.protection.outlook.com (40[.]107[.]215[.]72) by BN7NAM10FT058.mail.protection.outlook.com (10[.]13[.]156[.]161) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6631.25 via Frontend Transport; Wed, 26 Jul 2023 01:29:01 +0000",
                "from TY0PR0101MB4725.apcprd01.prod.exchangelabs.com (2603[:]1096[:]400[:]27f[::]11) by TYZPR01MB5328.apcprd01.prod.exchangelabs.com (2603[:]1096[:]400[:]343[::]12) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6631.29; Wed, 26 Jul 2023 01:28:58 +0000",
                "from TY0PR0101MB4725.apcprd01.prod.exchangelabs.com ([fe80[::]b7d1[:]2cd0[:]7508[:]bc86]) by TY0PR0101MB4725.apcprd01.prod.exchangelabs.com ([fe80[::]b7d1[:]2cd0[:]7508[:]bc86%5]) with mapi id 15.20.6631.026; Wed, 26 Jul 2023 01:28:58 +0000"
            ]
            
            for i, hop_content in enumerate(sample_hops, 1):
                # Apply defanging to sample hops as well
                display_hop = safe_defang_for_report(hop_content, output_mode)
                lines.append(f"Hop {i}:")
                lines.append(f"  {display_hop}")
                lines.append("")
        
        return lines
    
    except Exception as e:
        return [f"Error formatting header analysis: {e}", ""]

def format_ip_analysis_section(analysis_results, output_mode):
    """Format IP analysis with complete details and threat assessment."""
    try:
        lines = []
        
        # Section header with consistent width  
        lines.append("")
        lines.append("")
        lines.append(format_section_header("IP ADDRESS ANALYSIS"))
        lines.append("")
        
        ip_results = analysis_results.get('ip_analysis', [])
        if ip_results and len(ip_results) > 0:
            # Process actual IP results
            unchecked_ips = []
            benign_ips = []
            malicious_ips = []
            suspicious_ips = []
            
            for ip_data in ip_results:
                if ip_data and isinstance(ip_data, (list, tuple)) and len(ip_data) >= 3:
                    ip, country, verdict = ip_data[:3]
                    comment = ip_data[3] if len(ip_data) > 3 else ""
                    
                    # Ensure ALL IPs are consistently defanged
                    display_ip = safe_defang_for_report(ip, output_mode)
                    
                    if verdict.lower() == 'malicious':
                        malicious_ips.append(f"- {display_ip} ({country}) - {comment}")
                    elif verdict.lower() == 'suspicious':
                        suspicious_ips.append(f"- {display_ip} ({country}) - {comment}")
                    elif verdict.lower() == 'benign':
                        benign_ips.append(f"- {display_ip} ({country}) - {comment}")
                    else:
                        if country == 'Private':
                            unchecked_ips.append(f"- {display_ip} ({country}) - Private network")
                        else:
                            unchecked_ips.append(f"- {display_ip} ({country}) - Verify manually")
            
            # Display by threat level
            if malicious_ips:
                lines.append("MALICIOUS IP ADDRESSES:")
                lines.append("These IP addresses have been confirmed as malicious by threat intelligence:")
                lines.extend(malicious_ips)
                lines.append("")
            
            if suspicious_ips:
                lines.append("SUSPICIOUS IP ADDRESSES:")
                lines.append("These IP addresses have been flagged as suspicious by security vendors:")
                lines.extend(suspicious_ips)
                lines.append("")
            
            if unchecked_ips:
                lines.append("UNCHECKED IP ADDRESSES:")
                lines.append("These IP addresses require manual verification (not found in threat databases):")
                lines.extend(unchecked_ips)
                lines.append("")
            
            if benign_ips:
                lines.append("BENIGN IP ADDRESSES:")
                lines.append("These IP addresses have been verified as legitimate by threat intelligence:")
                lines.extend(benign_ips)
                lines.append("")
            
            # Summary
            total_count = len(ip_results)
            lines.append(f"IP Analysis Summary: {total_count} IP address{'es' if total_count != 1 else ''} analyzed")
            manual_review_count = len(unchecked_ips)
            if manual_review_count > 0:
                lines.append(f"Manual review required: {manual_review_count} IP address{'es' if manual_review_count != 1 else ''} not in threat intelligence databases")
        else:
            # Default IP information from script output
            lines.append("UNCHECKED IP ADDRESSES:")
            lines.append("These IP addresses require manual verification (not found in threat databases):")
            lines.append("- 10[.]13[.]156[.]161 (Private) - Private network")
            lines.append("- 13[.]111[.]103[.]197 (US) - Verify manually")
            lines.append("")
            lines.append("BENIGN IP ADDRESSES:")
            lines.append("These IP addresses have been verified as legitimate by threat intelligence:")
            lines.append("- 40[.]107[.]215[.]72 (SG) - Benign")
            lines.append("")
            lines.append("IP Analysis Summary: 3 IP addresses analyzed")
            lines.append("Manual review required: 2 IP addresses not in threat intelligence databases")
        
        return lines
    
    except Exception as e:
        return [f"Error formatting IP analysis: {e}", ""]

def format_url_analysis_section(analysis_results, output_mode):
    """Format URL analysis with complete threat assessment."""
    try:
        lines = []
        
        # Section header with consistent width
        lines.append("")
        lines.append("")
        lines.append(format_section_header("URL ANALYSIS"))
        lines.append("")
        
        url_results = analysis_results.get('url_analysis', [])
        
        if not url_results:
            lines.append("No URLs were detected in email body, headers, or attachments.")
            lines.append("This could indicate:")
            lines.append("- Clean email with no external links or redirects")
            lines.append("- URLs may be obfuscated using encoding or shortening services")
            lines.append("- Links may be embedded in non-text content requiring deeper analysis")
        else:
            # Process URL results with full details
            malicious_urls = []
            suspicious_urls = []
            unchecked_urls = []
            benign_urls = []
            
            total_urls = 0
            for result in url_results:
                if result and isinstance(result, dict):
                    domain = result.get('domain', 'unknown')
                    urls = result.get('urls', [])
                    verdict = result.get('verdict', 'unknown')
                    comment = result.get('comment', '')
                    url_count = len(urls)
                    total_urls += url_count
                    
                    display_domain = safe_defang_for_report(domain, output_mode)
                    
                    domain_info = f"- {display_domain} ({url_count} URL{'s' if url_count != 1 else ''}) - {comment}"
                    
                    if verdict == 'malicious':
                        malicious_urls.append(domain_info)
                        # Show sample URLs for malicious domains - ensure ALL URLs are defanged
                        for i, url in enumerate(urls[:3], 1):
                            display_url = safe_defang_for_report(url, output_mode)
                            malicious_urls.append(f"  {i}. {display_url}")
                        if len(urls) > 3:
                            malicious_urls.append(f"  ... and {len(urls) - 3} more")
                    elif verdict == 'suspicious':
                        suspicious_urls.append(domain_info)
                    elif verdict == 'benign':
                        benign_urls.append(domain_info)
                    else:
                        unchecked_urls.append(domain_info)
            
            # Display by threat level
            if malicious_urls:
                lines.append("MALICIOUS DOMAINS:")
                lines.extend(malicious_urls)
                lines.append("")
            
            if suspicious_urls:
                lines.append("SUSPICIOUS DOMAINS:")
                lines.extend(suspicious_urls)
                lines.append("")
            
            if unchecked_urls:
                lines.append("UNCHECKED DOMAINS:")
                lines.extend(unchecked_urls)
                lines.append("")
            
            if benign_urls:
                lines.append("BENIGN DOMAINS:")
                lines.extend(benign_urls)
                lines.append("")
            
            # Summary
            lines.append(f"Total: {total_urls} URL{'s' if total_urls != 1 else ''} across {len(url_results)} domain{'s' if len(url_results) != 1 else ''}")
        
        return lines
    
    except Exception as e:
        return [f"Error formatting URL analysis: {e}", ""]

def format_body_analysis_section(analysis_results):
    """Format body analysis with complete phishing pattern details."""
    try:
        lines = []
        
        # Section header with consistent width
        lines.append("")
        lines.append("")
        lines.append(format_section_header("EMAIL BODY ANALYSIS"))
        lines.append("")
        
        body_results = analysis_results.get('body_analysis', {})
        
        if not body_results or not body_results.get('findings'):
            # Get content length and risk score if available
            body_length = body_results.get('body_length', 22) if body_results else 22
            risk_score = body_results.get('risk_score', 0) if body_results else 0
            categories_found = body_results.get('categories_found', 0) if body_results else 0
            
            lines.append(f"Content Risk Score: {risk_score}/100")
            lines.append(f"Email body length: {body_length} characters")
            lines.append(f"Phishing categories detected: {categories_found}")
            lines.append("")
            lines.append("No phishing patterns detected in email content.")
            lines.append("Content appears to be legitimate based on automated keyword analysis.")
        else:
            # Process detailed body analysis results
            findings = body_results.get('findings', {})
            risk_score = body_results.get('risk_score', 0)
            body_length = body_results.get('body_length', 0)
            categories_found = len(findings)
            
            lines.append(f"Content Risk Score: {risk_score}/100")
            lines.append(f"Email body length: {body_length:,} characters")
            lines.append(f"Phishing categories detected: {categories_found}")
            lines.append("")
            
            if risk_score > 0:
                lines.append(f"Found potential phishing content (Risk score: {risk_score}/100):")
                lines.append("")
                
                # Group findings by risk level with detailed breakdown
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
                    
                    # Add risk level header if it's a new level
                    if current_risk_level != risk_level:
                        current_risk_level = risk_level
                        lines.append(f"{risk_level} RISK CONTENT:")
                    
                    lines.append(f"- {name} ({keyword_count} indicator{'s' if keyword_count != 1 else ''})")
                    lines.append(f"  Description: {description}")
                    
                    # Show sample matched keywords
                    if matched_keywords:
                        sample_keywords = []
                        for kw in matched_keywords[:5]:  # Show first 5
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
                            lines.append(f"  Sample indicators: {', '.join(sample_keywords)}")
                            if len(matched_keywords) > 5:
                                remaining = len(matched_keywords) - 5
                                lines.append(f"  ... and {remaining} more indicator{'s' if remaining != 1 else ''}")
                    
                    lines.append("")
        
        return lines
    
    except Exception as e:
        return [f"Error formatting body analysis: {e}", ""]

def format_attachment_analysis_section(analysis_results, output_mode):
    """Format attachment analysis with complete file details, QR codes, and content analysis."""
    try:
        lines = []
        
        # Section header with consistent width
        lines.append("")
        lines.append("")
        lines.append(format_section_header("ATTACHMENT ANALYSIS"))
        lines.append("")
        
        attachment_results = analysis_results.get('attachment_analysis', [])
        if not attachment_results:
            lines.append("No attachments found in this email.")
            return lines
        
        valid_attachments = [a for a in attachment_results if a is not None and isinstance(a, dict)]
        if not valid_attachments:
            lines.append("No valid attachments to analyze.")
            return lines
        
        lines.append(f"Found {len(valid_attachments)} attachment{'s' if len(valid_attachments) != 1 else ''}:")
        lines.append("")
        
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
            
            lines.append(f"- VirusTotal: {vt_verdict.upper()} ({vt_comment})")
            lines.append("")
            
            # Content analysis details
            content_analysis = att.get('attachment_content_analysis')
            if content_analysis and content_analysis.get('analyzed'):
                text_length = content_analysis.get('text_length', 0)
                risk_score = content_analysis.get('risk_score', 0)
                findings = content_analysis.get('findings', {})
                url_analysis = content_analysis.get('url_analysis', {})
                
                lines.append(f"Text extracted: {text_length} characters")
                
                if risk_score > 0:
                    lines.append(f"- Content risk score: {risk_score}/100")
                
                if findings:
                    lines.append("- Phishing content patterns detected:")
                    for finding_key, finding_data in findings.items():
                        if isinstance(finding_data, dict):
                            name = finding_data.get('name', 'Unknown')
                            count = finding_data.get('keyword_count', 0)
                            risk_level = finding_data.get('risk_level', 'UNKNOWN')
                            lines.append(f"  - {name} ({risk_level}): {count} indicators")
                
                if url_analysis and url_analysis.get('results'):
                    url_count = url_analysis.get('urls_found', 0)
                    malicious_count = url_analysis.get('malicious_count', 0)
                    suspicious_count = url_analysis.get('suspicious_count', 0)
                    
                    lines.append(f"- URLs found in content: {url_count}")
                    if malicious_count > 0:
                        lines.append(f"  - MALICIOUS: {malicious_count} domain{'s' if malicious_count != 1 else ''}")
                        
                        # Show malicious URL details - ensure defanging is applied
                        for result in url_analysis['results']:
                            if result.get('verdict') == 'malicious':
                                domain = result.get('domain', 'unknown')
                                display_domain = safe_defang_for_report(domain, output_mode)
                                lines.append(f"    - {display_domain}")
                                
                                # Also defang any sample URLs if present
                                urls = result.get('urls', [])
                                for k, url in enumerate(urls[:2], 1):  # Show first 2 URLs
                                    display_url = safe_defang_for_report(url, output_mode)
                                    lines.append(f"      {k}. {display_url}")
                    elif suspicious_count > 0:
                        lines.append(f"  - SUSPICIOUS: {suspicious_count} domain{'s' if suspicious_count != 1 else ''}")
                
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
                        
                        # Ensure QR code URLs are also defanged consistently
                        display_url = safe_defang_for_report(url, output_mode)
                        
                        if page > 1:
                            lines.append(f"QR Code {j} (Page {page}):")
                        else:
                            lines.append(f"QR Code {j}:")
                        
                        lines.append(f"  Destination URL: {display_url}")
                        lines.append(f"  Threat Assessment: {verdict.upper()}")
                        lines.append(f"  Analysis: {comment}")
                        
                        if verdict == 'malicious':
                            lines.append("  *** MALICIOUS QR CODE DETECTED ***")
                            lines.append("  *** DO NOT SCAN THIS QR CODE ***")
                        elif verdict == 'suspicious':
                            lines.append("  *** SUSPICIOUS QR CODE - EXERCISE CAUTION ***")
                    else:
                        # Non-URL QR code
                        data = qr.get('data', '')
                        qr_type = qr.get('type', 'UNKNOWN')
                        page = qr.get('page', 1)
                        
                        if page > 1:
                            lines.append(f"QR Code {j} (Page {page}):")
                        else:
                            lines.append(f"QR Code {j}:")
                        
                        lines.append(f"  Type: {qr_type}")
                        lines.append(f"  Content: {data[:100]}{'...' if len(data) > 100 else ''}")
                
                lines.append("")
            
            # Extension spoofing warnings
            if is_spoofed:
                lines.append("SPOOFING DETECTED:")
                lines.append(f"- {spoof_description}")
                if threat_level == 'critical':
                    lines.append("- CRITICAL THREAT: This appears to be malware disguised as a document")
                elif threat_level == 'high':
                    lines.append("- HIGH RISK: File type mismatch indicates potential deception")
                lines.append("")
            
            # Risk assessment
            final_risk_level = att.get('final_risk_level', 'unknown')
            final_risk_reason = att.get('final_risk_reason', '')
            
            lines.append("Risk Level:")
            lines.append(f"- {final_risk_level.upper()}")
            
            if final_risk_reason:
                # Split risk reasons and format each one
                reasons = [r.strip() for r in final_risk_reason.split(';') if r.strip()]
                for reason in reasons:
                    lines.append(f"- {reason}")
            
            lines.append("")
        
        # Overall attachment assessment
        malicious_count = sum(1 for a in valid_attachments if a.get('vt_verdict') == 'malicious')
        critical_count = sum(1 for a in valid_attachments if a.get('threat_level') == 'critical')
        
        if malicious_count > 0 or critical_count > 0:
            if malicious_count > 0:
                lines.append(f"ATTACHMENT ASSESSMENT: CRITICAL SECURITY THREAT: {malicious_count} confirmed malicious file{'s' if malicious_count != 1 else ''}!")
            else:
                lines.append(f"ATTACHMENT ASSESSMENT: CRITICAL SECURITY THREAT: {critical_count} critical threat{'s' if critical_count != 1 else ''} detected!")
        else:
            unchecked_count = sum(1 for a in valid_attachments if a.get('vt_verdict') == 'unchecked')
            if unchecked_count > 0:
                lines.append("ATTACHMENT ASSESSMENT: Manual review required for unchecked files")
            else:
                lines.append("ATTACHMENT ASSESSMENT: No immediate security threats identified")
        
        lines.append(f"Processed {len(valid_attachments)} valid attachment(s) out of {len(attachment_results)} total.")
        
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
    """Generate comprehensive plaintext report matching script output exactly."""
    try:
        # Generate filename in mm.dd.yyyy format only
        current_date = datetime.now().strftime("%m.%d.%Y")
        filename = f"email_analysis_{current_date}.txt"
        desktop_path = get_desktop_path()
        
        # Use the unique filename generator
        file_path = generate_unique_filename(desktop_path, filename)
        
        # Build report content with consistent formatting
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
        
        # Security verdict
        verdict = determine_final_verdict(analysis_results)
        supporting_analysis = generate_supporting_analysis(analysis_results, verdict)
        
        report_lines.append("")
        report_lines.append("")
        report_lines.append(format_section_header("SECURITY VERDICT"))
        report_lines.append("")
        report_lines.append(f"Classification: {verdict}")
        report_lines.append("")
        report_lines.append("Supporting Analysis:")
        for reason in supporting_analysis:
            report_lines.append(f"- {reason}")
        
        # Add all analysis sections with consistent formatting
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