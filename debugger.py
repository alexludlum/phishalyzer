#!/usr/bin/env python3
"""
Diagnostic to properly extract data from MSG attachments
"""

import sys
import os
import extract_msg
import io

def diagnose_msg_data_extraction(file_path):
    """Diagnose different methods to extract MSG attachment data"""
    print("=== MSG DATA EXTRACTION DIAGNOSTIC ===")
    
    try:
        # Load MSG
        print("Loading MSG...")
        msg = extract_msg.Message(file_path)
        print("MSG loaded OK")
        
        # Check attachments
        if hasattr(msg, 'attachments'):
            attachments = getattr(msg, 'attachments', [])
            print(f"MSG has {len(attachments)} attachments")
            
            if attachments:
                att = attachments[0]  # Check first attachment
                print("\nFirst attachment analysis:")
                
                # Get filename
                filename = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', 'unknown')
                print(f"  Filename: {filename}")
                
                # Check all attributes
                print("  Available attributes:")
                for attr in dir(att):
                    if not attr.startswith('_'):
                        try:
                            value = getattr(att, attr)
                            if not callable(value):
                                print(f"    {attr}: {type(value)} = {repr(str(value)[:50])}")
                        except:
                            print(f"    {attr}: <error accessing>")
                
                # Method 1: Direct data attribute
                print("\n  Method 1: Direct .data attribute")
                try:
                    data = getattr(att, 'data', None)
                    print(f"    Data type: {type(data)}")
                    
                    if data is not None:
                        if hasattr(data, '__len__') and not isinstance(data, extract_msg.Message):
                            print(f"    Data length: {len(data)} bytes")
                            if len(data) > 0:
                                print(f"    First 16 bytes: {data[:16].hex()}")
                                if data.startswith(b'%PDF-'):
                                    print("    *** PDF MAGIC FOUND! ***")
                        else:
                            print(f"    Data is not raw bytes (type: {type(data)})")
                    else:
                        print("    No .data attribute")
                except Exception as e:
                    print(f"    Error: {e}")
                
                # Method 2: Try save() method
                print("\n  Method 2: Using .save() method")
                try:
                    if hasattr(att, 'save') and callable(att.save):
                        buffer = io.BytesIO()
                        att.save(buffer)
                        saved_data = buffer.getvalue()
                        print(f"    Saved data length: {len(saved_data)} bytes")
                        if len(saved_data) > 0:
                            print(f"    First 16 bytes: {saved_data[:16].hex()}")
                            if saved_data.startswith(b'%PDF-'):
                                print("    *** PDF MAGIC FOUND via save()! ***")
                        buffer.close()
                    else:
                        print("    No .save() method available")
                except Exception as e:
                    print(f"    Save error: {e}")
                
                # Method 3: Check if it's an embedded message
                print("\n  Method 3: Check for embedded message")
                try:
                    data = getattr(att, 'data', None)
                    if isinstance(data, extract_msg.Message):
                        print("    Attachment is an embedded message!")
                        print("    This might be a nested MSG file")
                        
                        # Try to get the embedded message's attachments
                        if hasattr(data, 'attachments'):
                            nested_attachments = getattr(data, 'attachments', [])
                            print(f"    Nested message has {len(nested_attachments)} attachments")
                            
                            if nested_attachments:
                                nested_att = nested_attachments[0]
                                nested_filename = getattr(nested_att, 'longFilename', None) or getattr(nested_att, 'shortFilename', 'unknown')
                                print(f"    Nested attachment filename: {nested_filename}")
                                
                                nested_data = getattr(nested_att, 'data', None)
                                if nested_data and hasattr(nested_data, '__len__'):
                                    try:
                                        print(f"    Nested data length: {len(nested_data)} bytes")
                                        if len(nested_data) > 0:
                                            print(f"    Nested first 16 bytes: {nested_data[:16].hex()}")
                                            if nested_data.startswith(b'%PDF-'):
                                                print("    *** PDF MAGIC FOUND in nested attachment! ***")
                                    except:
                                        print("    Nested data length check failed")
                    else:
                        print("    Not an embedded message")
                except Exception as e:
                    print(f"    Embedded message check error: {e}")
                
                # Method 4: Try alternative extraction
                print("\n  Method 4: Alternative extraction methods")
                try:
                    # Check for raw content
                    if hasattr(att, '_raw_data'):
                        raw_data = getattr(att, '_raw_data', None)
                        if raw_data:
                            print(f"    Raw data found: {len(raw_data)} bytes")
                    
                    # Check for stream
                    if hasattr(att, '_stream'):
                        stream = getattr(att, '_stream', None)
                        if stream:
                            print(f"    Stream found: {type(stream)}")
                            
                except Exception as e:
                    print(f"    Alternative extraction error: {e}")
                
        else:
            print("No attachments found")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python msg_data_diagnostic.py <msg_file_path>")
        sys.exit(1)
    
    diagnose_msg_data_extraction(sys.argv[1])