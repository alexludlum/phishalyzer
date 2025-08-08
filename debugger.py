#!/usr/bin/env python3
"""
Debug script to diagnose email parsing issues
"""

import sys
import os
from analyzer import parser

def debug_email_parsing(file_path):
    """Debug email parsing step by step"""
    print("=== EMAIL PARSING DIAGNOSTIC ===")
    
    # Step 1: Check file exists and basic info
    print(f"1. Checking file: {file_path}")
    if not os.path.exists(file_path):
        print(f"   ERROR: File does not exist!")
        return
    
    file_size = os.path.getsize(file_path)
    print(f"   File size: {file_size} bytes")
    
    # Step 2: Check file content preview
    print(f"\n2. File content preview (first 500 chars):")
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(500)
            print(f"   Content: {repr(content[:200])}...")
    except Exception as e:
        print(f"   ERROR reading file: {e}")
        return
    
    # Step 3: Try parsing
    print(f"\n3. Attempting to parse email:")
    try:
        msg_obj, filetype = parser.load_email(file_path)
        print(f"   Parse result: msg_obj = {type(msg_obj)}")
        print(f"   Detected filetype: {filetype}")
        
        if msg_obj is None:
            print("   ERROR: msg_obj is None!")
            return
        
        # Step 4: Check message object properties
        print(f"\n4. Message object analysis:")
        print(f"   Has 'get' method: {hasattr(msg_obj, 'get')}")
        print(f"   Has 'items' method: {hasattr(msg_obj, 'items')}")
        print(f"   Has 'walk' method: {hasattr(msg_obj, 'walk')}")
        print(f"   Has 'is_multipart' method: {hasattr(msg_obj, 'is_multipart')}")
        
        # Step 5: Try to get basic headers
        print(f"\n5. Basic header extraction:")
        try:
            subject = msg_obj.get('Subject', 'No Subject') if hasattr(msg_obj, 'get') else 'No get method'
            print(f"   Subject: {subject}")
            
            from_header = msg_obj.get('From', 'No From') if hasattr(msg_obj, 'get') else 'No get method'
            print(f"   From: {from_header}")
            
            # Try to get all headers
            if hasattr(msg_obj, 'items'):
                headers = dict(msg_obj.items())
                print(f"   Total headers found: {len(headers)}")
                print(f"   Header keys: {list(headers.keys())[:5]}...")  # First 5 headers
            else:
                print("   No items() method available")
                
        except Exception as e:
            print(f"   ERROR getting headers: {e}")
        
        # Step 6: Check multipart and body
        print(f"\n6. Body content analysis:")
        try:
            if hasattr(msg_obj, 'is_multipart'):
                is_multipart = msg_obj.is_multipart()
                print(f"   Is multipart: {is_multipart}")
                
                if is_multipart and hasattr(msg_obj, 'walk'):
                    parts = list(msg_obj.walk())
                    print(f"   Number of parts: {len(parts)}")
                else:
                    print("   Single part message or no walk() method")
            else:
                print("   No is_multipart() method")
                
            # Try to get payload
            if hasattr(msg_obj, 'get_payload'):
                payload = msg_obj.get_payload()
                print(f"   Payload type: {type(payload)}")
                if isinstance(payload, str):
                    print(f"   Payload length: {len(payload)} chars")
                    print(f"   Payload preview: {repr(payload[:100])}...")
                elif isinstance(payload, list):
                    print(f"   Payload is list with {len(payload)} items")
                else:
                    print(f"   Payload: {payload}")
            else:
                print("   No get_payload() method")
                
        except Exception as e:
            print(f"   ERROR analyzing body: {e}")
            
    except Exception as e:
        print(f"   PARSE ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python debug_parser.py <email_file_path>")
        sys.exit(1)
    
    debug_email_parsing(sys.argv[1])