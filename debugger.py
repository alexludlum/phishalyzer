#!/usr/bin/env python3
"""
Test the IPv6 vs timestamp conflict resolution
"""

import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'analyzer'))

try:
    from compatible_output import output
    print("✓ Universal output system loaded")
except ImportError as e:
    print(f"✗ Import failed: {e}")
    sys.exit(1)

def test_improved_patterns():
    """Test the improved, more precise patterns"""
    
    print("\n" + "="*100)
    print("IMPROVED PATTERN PRECISION TEST")
    print("="*100)
    
    # More precise IPv4 patterns
    IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    DEFANGED_IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b')
    
    # Much more precise IPv6 patterns
    IPV6_LOOPBACK_PATTERN = re.compile(r'\b::1\b')
    IPV6_FULL_PATTERN = re.compile(r'\b[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{3,4}:[0-9a-fA-F]{2,}\b')
    DEFANGED_IPV6_FULL_PATTERN = re.compile(r'\b[0-9a-fA-F]{4}\[:\][0-9a-fA-F]{4}\[:\][0-9a-fA-F]{3,4}\[:\][0-9a-fA-F]{2,}\b')
    
    # Precise timestamp pattern
    TIMESTAMP_PATTERN = re.compile(r'\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s*(?:[-+]\d{4})?\b')
    
    # Test cases from your actual data
    test_cases = [
        # Should be IPv6 (yellow)
        ("::1", "IPv6 loopback"),
        ("2603:10b6:408:e628", "IPv6 regular"),
        ("2603[:]10b6[:]408[:]e628", "IPv6 defanged"),
        ("2603[:]10b6[:]408[:]e6[:]cafe23", "IPv6 defanged long"),
        
        # Should be timestamps (blue)  
        ("Tue, 19 Sep 2023 18:36:46 +0000", "Full timestamp"),
        ("19 Sep 2023 18:36:45 +0000", "Date with time"),
        ("18:36:45", "Time only - should NOT be IPv6"),
        ("18:35:49 +0000", "Time with timezone"),
        
        # Mixed content
        ("from server (::1) by mail; Tue, 19 Sep 2023 18:36:46 +0000", "IPv6 + timestamp"),
        ("(2603[:]10b6[:]408[:]e628) id 15.20.6792.27; Tue, 19 Sep 2023 18:36:45 +0000", "Defanged IPv6 + timestamp")
    ]
    
    print("Testing pattern matching precision:")
    print()
    
    for test_input, description in test_cases:
        print(f"Testing: {description}")
        print(f"Input:   {test_input}")
        
        # Check what each pattern matches
        ipv4_matches = IPV4_PATTERN.findall(test_input)
        ipv4_defanged_matches = DEFANGED_IPV4_PATTERN.findall(test_input)
        ipv6_loopback_matches = IPV6_LOOPBACK_PATTERN.findall(test_input)
        ipv6_full_matches = IPV6_FULL_PATTERN.findall(test_input)
        ipv6_defanged_matches = DEFANGED_IPV6_FULL_PATTERN.findall(test_input)
        timestamp_matches = TIMESTAMP_PATTERN.findall(test_input)
        
        print(f"  IPv4 matches: {ipv4_matches}")
        print(f"  IPv4 defanged: {ipv4_defanged_matches}")
        print(f"  IPv6 loopback: {ipv6_loopback_matches}")
        print(f"  IPv6 full: {ipv6_full_matches}")
        print(f"  IPv6 defanged: {ipv6_defanged_matches}")
        print(f"  Timestamp: {timestamp_matches}")
        print()

def test_highlighting_order():
    """Test the correct highlighting order to prevent conflicts"""
    
    print("\n" + "="*100)
    print("HIGHLIGHTING ORDER TEST")
    print("="*100)
    
    def highlight_with_correct_order(text):
        """Apply highlighting in the correct order"""
        result = text
        
        # STEP 1: Timestamps FIRST (blue)
        timestamp_pattern = re.compile(r'\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s*(?:[-+]\d{4})?\b')
        
        def safe_timestamp_highlight(match):
            timestamp_text = match.group(0)
            if '[blue]' not in timestamp_text and '\033[' not in timestamp_text:
                return f'[blue]{timestamp_text}[/blue]'
            return timestamp_text
        
        result = re.sub(timestamp_pattern, safe_timestamp_highlight, result)
        
        # Timezone markers
        timezone_pattern = re.compile(r'\([A-Z]{2,4}\)')
        result = re.sub(timezone_pattern, lambda m: f'[blue]{m.group(0)}[/blue]', result)
        
        # STEP 2: IP addresses SECOND (yellow) - avoiding already colored areas
        def safe_ip_highlight(match):
            ip_text = match.group(0)
            if '[blue]' not in ip_text and '\033[' not in ip_text:
                return f'[yellow]{ip_text}[/yellow]'
            return ip_text
        
        # IPv4
        ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        defanged_ipv4_pattern = re.compile(r'\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b')
        result = re.sub(ipv4_pattern, safe_ip_highlight, result)
        result = re.sub(defanged_ipv4_pattern, safe_ip_highlight, result)
        
        # IPv6 - specific patterns only
        ipv6_loopback = re.compile(r'\b::1\b')
        ipv6_full = re.compile(r'\b[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{3,4}:[0-9a-fA-F]{2,}\b')
        ipv6_defanged = re.compile(r'\b[0-9a-fA-F]{4}\[:\][0-9a-fA-F]{4}\[:\][0-9a-fA-F]{3,4}\[:\][0-9a-fA-F]{2,}\b')
        
        result = re.sub(ipv6_loopback, safe_ip_highlight, result)
        result = re.sub(ipv6_full, safe_ip_highlight, result)
        result = re.sub(ipv6_defanged, safe_ip_highlight, result)
        
        return result
    
    # Test cases from your actual Received hops
    received_examples = [
        "from SA3PR19MB7370.namprd19.prod.outlook.com (::1) by MN0PR19MB6312.namprd19.prod.outlook.com with HTTPS; Tue, 19 Sep 2023 18:36:46 +0000",
        "from BN0PR03CA0023.namprd03.prod.outlook.com (2603[:]10b6[:]408[:]e628) by SA3PR19MB7370.namprd19.prod.outlook.com",
        "from BN8NAM11FT066.eop-nam11.prod.protection.outlook.com (2603[:]10b6[:]408[:]e6[:]cafe23) by BN0PR03CA0023.outlook.office365.com",
        "id 15.20.6792.27; Tue, 19 Sep 2023 18:36:45 +0000"
    ]
    
    for example in received_examples:
        print(f"Input:  {example}")
        highlighted = highlight_with_correct_order(example)
        print(f"Result: {highlighted}")
        output.print(f"Render: {highlighted}")
        print()

def test_specific_ipv6_patterns():
    """Test specific IPv6 patterns that should be caught"""
    
    print("\n" + "="*100)
    print("SPECIFIC IPv6 PATTERN TEST")
    print("="*100)
    
    # Test the exact IPv6 addresses from your screenshot
    ipv6_examples = [
        "::1",
        "2603:10b6:408:e628", 
        "2603[:]10b6[:]408[:]e628",
        "2603[:]10b6[:]408[:]e6[:]cafe23",
        "2603[:]10b6[:]806[:]317[::]17"
    ]
    
    # Improved IPv6 patterns
    patterns = {
        "Loopback": re.compile(r'\b::1\b'),
        "Full hex": re.compile(r'\b[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{3,4}:[0-9a-fA-F]{2,}\b'),
        "Defanged": re.compile(r'\b[0-9a-fA-F]{4}\[:\][0-9a-fA-F]{4}\[:\][0-9a-fA-F]{3,4}\[:\][0-9a-fA-F]{2,}\b'),
        "Complex defanged": re.compile(r'\b[0-9a-fA-F]{4}\[:\][0-9a-fA-F]{4}\[:\][0-9a-fA-F]{3,4}\[:\][0-9a-fA-F]{2,}(?:\[:\][0-9a-fA-F]*)*\b')
    }
    
    for ipv6 in ipv6_examples:
        print(f"Testing IPv6: {ipv6}")
        for pattern_name, pattern in patterns.items():
            matches = pattern.findall(ipv6)
            if matches:
                print(f"  ✓ Matched by {pattern_name}: {matches}")
                highlighted = re.sub(pattern, lambda m: f'[yellow]{m.group(0)}[/yellow]', ipv6)
                output.print(f"  Highlighted: {highlighted}")
            else:
                print(f"  ✗ Not matched by {pattern_name}")
        print()

def main():
    """Run all conflict resolution tests"""
    print("IPv6 vs TIMESTAMP CONFLICT RESOLUTION TEST")
    print("="*100)
    
    test_improved_patterns()
    test_highlighting_order()
    test_specific_ipv6_patterns()
    
    print("\n" + "="*100)
    print("EXPECTED RESULTS:")
    print("- Timestamps (18:36:45 +0000) should be BLUE")
    print("- IPv6 addresses (::1, 2603:10b6:408:e628) should be YELLOW")
    print("- No conflict between IPv6 and timestamp patterns")
    print("- Full IPv6 addresses should be completely highlighted")
    print("="*100)

if __name__ == "__main__":
    main()