"""
Defanging utilities for phishalyzer output.
Converts potentially dangerous URLs and IP addresses into safe, non-clickable formats.
"""

import re
from urllib.parse import urlparse

def defang_url(url):
    """
    Convert a URL into defanged format.
    Examples:
    - https://malicious.com -> https[:]//malicious[.]com
    - http://evil.domain.net/path -> http[:]//evil[.]domain[.]net/path
    - www.bad.site.org -> www[.]bad[.]site[.]org
    - user@malicious.domain.com -> user@malicious[.]domain[.]com
    """
    if not url or not isinstance(url, str):
        return url
    
    result = url
    
    # Handle email addresses first
    if '@' in result and '://' not in result:
        # It's an email address
        parts = result.split('@')
        if len(parts) == 2:
            username, domain = parts
            # Only defang the domain part
            domain = domain.replace('.', '[.]')
            result = f"{username}@{domain}"
        return result
    
    # Handle URLs with protocols
    if '://' in result:
        result = result.replace('://', '[:]//') 
        
        # Split on [:]// to separate protocol from the rest
        parts = result.split('[:]//', 1)
        if len(parts) == 2:
            protocol_part = parts[0] + '[:]'
            rest = parts[1]
            
            # Find where domain ends (first slash, question mark, or hash)
            domain_end = len(rest)
            for char in ['/', '?', '#']:
                pos = rest.find(char)
                if pos != -1 and pos < domain_end:
                    domain_end = pos
            
            domain_part = rest[:domain_end]
            path_part = rest[domain_end:]
            
            # Replace dots in domain only
            domain_part = domain_part.replace('.', '[.]')
            
            result = f"{protocol_part}//{domain_part}{path_part}"
    else:
        # No protocol, treat as domain-only (like www.example.com)
        # Only defang if it looks like a domain
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', result):
            # Find where domain ends
            domain_end = len(result)
            for char in ['/', '?', '#']:
                pos = result.find(char)
                if pos != -1 and pos < domain_end:
                    domain_end = pos
            
            domain_part = result[:domain_end]
            path_part = result[domain_end:]
            
            # Replace dots in domain only
            domain_part = domain_part.replace('.', '[.]')
            
            result = f"{domain_part}{path_part}"
    
    return result

def defang_ipv4(ip):
    """
    Convert an IPv4 address into defanged format.
    Example: 192.168.1.1 -> 192[.]168[.]1[.]1
    """
    if not ip or not isinstance(ip, str):
        return ip
    
    # Validate it's actually an IPv4 address
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return ip.replace('.', '[.]')
    
    return ip

def defang_ipv6(ip):
    """
    Convert an IPv6 address into defanged format.
    Example: 2001:db8::1 -> 2001[:]db8[::]1
    """
    if not ip or not isinstance(ip, str):
        return ip
    
    # Basic IPv6 pattern check
    if ':' in ip and re.match(r'^[0-9a-fA-F:]+$', ip):
        result = ip
        
        # Handle :: (consecutive colons) first
        if '::' in result:
            # Split by :: and process each part
            parts = result.split('::')
            processed_parts = []
            
            for part in parts:
                if part:  # Non-empty part
                    # Replace single colons with [:]
                    processed_parts.append(part.replace(':', '[:]'))
                else:
                    # Empty part (from split)
                    processed_parts.append('')
            
            # Join with [::]
            result = '[::]'.join(processed_parts)
        else:
            # No ::, just replace all colons
            result = result.replace(':', '[:]')
        
        return result
    
    return ip

def defang_ip(ip):
    """
    Auto-detect IP type and defang accordingly.
    """
    if not ip or not isinstance(ip, str):
        return ip
    
    if ':' in ip:
        return defang_ipv6(ip)
    elif '.' in ip:
        return defang_ipv4(ip)
    
    return ip

def defang_text(text, defang_urls=True, defang_ips=True):
    """
    Defang URLs and IPs found in a text string.
    
    Args:
        text: Input text to defang
        defang_urls: Whether to defang URLs
        defang_ips: Whether to defang IP addresses
    
    Returns:
        Defanged text
    """
    if not text or not isinstance(text, str):
        return text
    
    result = text
    
    if defang_urls:
        # URL patterns - order matters, do more specific patterns first
        url_patterns = [
            # Full URLs with protocols - use the original working pattern
            (r'https://[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            (r'http://[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            (r'ftp://[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            (r'ftps://[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            (r'sftp://[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            (r'smtp://[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            (r'smtps://[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            (r'ldap://[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            (r'ldaps://[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            (r'file://[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            (r'ssh://[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            (r'tel:[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            (r'mailto:[^\s<>"\']+', lambda m: defang_url(m.group(0))),
            # Email addresses - more specific pattern
            (r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', lambda m: defang_url(m.group(0))),
            # www domains
            (r'\bwww\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\']*)?', lambda m: defang_url(m.group(0))),
        ]
        
        for pattern, replacer in url_patterns:
            result = re.sub(pattern, replacer, result)
    
    if defang_ips:
        # IPv4 pattern - be more specific to avoid false positives
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        result = re.sub(ipv4_pattern, lambda m: defang_ipv4(m.group(0)), result)
        
        # IPv6 pattern (more comprehensive)
        ipv6_patterns = [
            r'\b[0-9a-fA-F:]+::[0-9a-fA-F:]*\b',  # Contains ::
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'  # Full form
        ]
        for pattern in ipv6_patterns:
            result = re.sub(pattern, lambda m: defang_ipv6(m.group(0)), result)
    
    return result

def should_defang():
    """
    Check if defanging is enabled based on global output mode.
    """
    try:
        import sys
        
        # Check both 'phishalyzer' and '__main__' module names
        for module_name in ['phishalyzer', '__main__']:
            if module_name in sys.modules:
                phishalyzer_module = sys.modules[module_name]
                output_mode = getattr(phishalyzer_module, 'output_mode', None)
                if output_mode == 'defanged':
                    return True
    except (ImportError, AttributeError):
        pass
    
    return False

if __name__ == "__main__":
    # Simple test when run directly
    print("Testing defang functions:")
    print("URL:", defang_url("https://malicious.com"))
    print("IPv4:", defang_ipv4("192.168.1.1"))
    print("IPv6:", defang_ipv6("2001:db8::1"))
    print("Text:", defang_text("Visit https://evil.com or 192.168.1.1"))