import argparse
import os
import sys
import platform
from analyzer import parser
from analyzer import header_analyzer
from analyzer import ioc_extractor
from analyzer import url_extractor
from analyzer import attachment_analyzer
from analyzer import body_analyzer
from analyzer import defanger
from datetime import datetime
from analyzer import report_generator

# Import the universal output system
try:
    from analyzer.compatible_output import output, print_header, print_status
    COMPATIBLE_OUTPUT = True
except ImportError:
    # Fallback if compatible_output module isn't available
    COMPATIBLE_OUTPUT = False

API_KEY_FILE = os.path.expanduser("~/.phishalyzer_vt_api_key")
OUTPUT_MODE_FILE = os.path.expanduser("~/.phishalyzer_output_mode")

output_mode = "fanged"  # default output mode - accessible globally

# Global variables to store last analysis results
last_url_analysis_results = None
last_received_hops = None
last_body_analysis_results = None
last_attachment_results = None
last_analyzed_file_path = None
last_analyzed_file_type = None
last_ip_analysis_results = None
last_header_analysis = None
last_analyzed_msg_obj = None

def check_defang_mode():
    """Debug function to check current defang mode"""
    try:
        if os.path.exists(OUTPUT_MODE_FILE):
            with open(OUTPUT_MODE_FILE, "r", encoding='utf-8') as f:
                content = f.read().strip()
                return content
        return "fanged"  # default
    except:
        return "fanged"

def apply_defanging(text):
    """Centralized defanging function that ALWAYS works when in defanged mode"""
    if not text or not isinstance(text, str):
        return text
    
    # Check current mode
    current_mode = check_defang_mode()
    if current_mode != "defanged":
        return text  # Don't defang if not in defanged mode
    
    # Apply defanging transformations
    result = text
    
    # Replace protocols
    result = result.replace('https://', 'https[:]//') 
    result = result.replace('http://', 'http[:]//') 
    result = result.replace('ftp://', 'ftp[:]//') 
    
    # FIXED: Check if this looks like a domain that's missing dots
    # (e.g., "mail123-ripplenet" should be "mail123-ripple.net")
    if '.' not in result and not result.startswith(('http', 'https', 'ftp')):
        # Special cases that need manual handling
        special_cases = [
            # Pattern: (search_string, replacement)
            ('getbeeio', 'getbee[.]io'),
            ('linkcoindesk', 'link[.]coindesk[.]com'),  # Added this
            ('coindesk', 'coindesk[.]com'),
            ('ripplenet', 'ripple[.]net'),
            ('sailthrucom', 'sailthru[.]com'),
        ]
        
        # Apply special case replacements
        for search, replacement in special_cases:
            if result.endswith(search) or result == search:  # More precise matching
                # Replace only the matching part at the end
                if result.endswith(search):
                    prefix = result[:-len(search)]
                    result = prefix + replacement
                else:
                    result = replacement
                break  # Only apply one replacement
        
        # If no special case matched, try generic TLD detection
        if '[.]' not in result:
            # Common TLD patterns at the end of domains
            tld_patterns = [
                ('com', '[.]com'),
                ('net', '[.]net'),
                ('org', '[.]org'),
                ('edu', '[.]edu'),
                ('gov', '[.]gov'),
                ('mil', '[.]mil'),
                ('int', '[.]int'),
                ('io', '[.]io'),
                ('co', '[.]co'),
                ('uk', '[.]uk'),
                ('de', '[.]de'),
                ('fr', '[.]fr'),
                ('ru', '[.]ru'),
                ('cn', '[.]cn'),
                ('jp', '[.]jp'),
                ('au', '[.]au'),
                ('ca', '[.]ca'),
                ('info', '[.]info'),
                ('biz', '[.]biz'),
                ('tv', '[.]tv'),
                ('cc', '[.]cc'),
                ('me', '[.]me')
            ]
            
            # Check if domain ends with a TLD (without dot)
            for tld, replacement in tld_patterns:
                if result.endswith(tld) and len(result) > len(tld):
                    # Make sure we're at a word boundary
                    prefix = result[:-len(tld)]
                    if prefix and prefix[-1].isalnum():
                        # This looks like a domain missing its dot
                        result = prefix + replacement
                        break
    
    # Replace dots in domains (for already properly formatted domains)
    else:
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
        
        # Handle any remaining dots in the middle of domains
        # But be careful not to replace dots that are already part of [.]
        if '.' in result and '[.]' not in result:
            # This is a domain with dots that weren't caught by TLD replacement
            result = result.replace('.', '[.]')
    
    return result

def print_section_header(title: str):
    """Print a standardized section header with consistent formatting."""
    if COMPATIBLE_OUTPUT:
        print_header(title)
    else:
        # Fallback for basic terminals
        total_width = 50
        title_with_spaces = f" {title.upper()} "
        padding_needed = total_width - len(title_with_spaces)
        left_padding = padding_needed // 2
        right_padding = padding_needed - left_padding
        header_line = "=" * left_padding + title_with_spaces + "=" * right_padding
        print(f"\n\n{header_line}\n")

def safe_file_read(filepath, default_value=""):
    """Safely read a file with error handling."""
    try:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding='utf-8') as f:
                content = f.read().strip()
                return content if content else default_value
    except (PermissionError, IOError, OSError, UnicodeDecodeError) as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Warning: Could not read {os.path.basename(filepath)}: {e}", "warning")
        else:
            print(f"Warning: Could not read {os.path.basename(filepath)}: {e}")
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Unexpected error reading {os.path.basename(filepath)}: {e}", "warning")
        else:
            print(f"Unexpected error reading {os.path.basename(filepath)}: {e}")
    return default_value

def safe_file_write(filepath, content):
    """Safely write to a file with error handling."""
    try:
        with open(filepath, "w", encoding='utf-8') as f:
            f.write(content.strip())
        return True
    except (PermissionError, IOError, OSError) as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error: Could not save to {os.path.basename(filepath)}: {e}", "error")
            print_status("Settings will not persist between sessions.", "warning")
        else:
            print(f"Error: Could not save to {os.path.basename(filepath)}: {e}")
            print("Settings will not persist between sessions.")
        return False
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Unexpected error saving {os.path.basename(filepath)}: {e}", "error")
        else:
            print(f"Unexpected error saving {os.path.basename(filepath)}: {e}")
        return False

def safe_file_delete(filepath):
    """Safely delete a file with error handling."""
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
        else:
            return False
    except (PermissionError, IOError, OSError) as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error: Could not delete {os.path.basename(filepath)}: {e}", "error")
        else:
            print(f"Error: Could not delete {os.path.basename(filepath)}: {e}")
        return False
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Unexpected error deleting {os.path.basename(filepath)}: {e}", "error")
        else:
            print(f"Unexpected error deleting {os.path.basename(filepath)}: {e}")
        return False

def get_saved_output_mode():
    """Get saved output mode from file with error handling."""
    try:
        content = safe_file_read(OUTPUT_MODE_FILE, "fanged")
        if content in ['fanged', 'defanged']:
            return content
    except Exception:
        pass
    return "fanged"  # default fallback

def save_output_mode(mode: str):
    """Save output mode to file with error handling."""
    try:
        if mode not in ['fanged', 'defanged']:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error: Invalid output mode '{mode}'", "error")
            else:
                print(f"Error: Invalid output mode '{mode}'")
            return False
        return safe_file_write(OUTPUT_MODE_FILE, mode)
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error saving output mode: {e}", "error")
        else:
            print(f"Error saving output mode: {e}")
        return False

def get_saved_api_key():
    """Get saved VirusTotal API key from file with error handling."""
    try:
        content = safe_file_read(API_KEY_FILE, "")
        if content and len(content) > 10:  # Basic validation
            return content
    except Exception:
        pass
    return None

def save_api_key(key: str):
    """Save VirusTotal API key to file with error handling."""
    try:
        if not key or len(key.strip()) < 10:
            if COMPATIBLE_OUTPUT:
                print_status("Error: API key appears invalid (too short)", "error")
            else:
                print("Error: API key appears invalid (too short)")
            return False
        return safe_file_write(API_KEY_FILE, key)
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error saving API key: {e}", "error")
        else:
            print(f"Error saving API key: {e}")
        return False

def safe_input(prompt, default=""):
    """Safely get user input with interruption handling."""
    try:
        response = input(prompt).strip()
        return response if response else default
    except (KeyboardInterrupt, EOFError):
        print("\n\nOperation cancelled.")
        return None
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Input error: {e}", "error")
        else:
            print(f"Input error: {e}")
        return default

def prompt_api_key_menu():
    """Handle VirusTotal API key management menu with error handling."""
    try:
        saved_key = get_saved_api_key()
        if saved_key:
            while True:
                try:
                    if COMPATIBLE_OUTPUT:
                        output.print("\n[blue]VirusTotal API Settings:[/blue]")
                        output.print("[blue]1:[/blue] View current API key")
                        output.print("[blue]2:[/blue] Delete API key")
                        output.print("[blue]3:[/blue] Enter a new API key")
                        output.print("[blue]4:[/blue] Return to main menu")
                    else:
                        print("\nVirusTotal API Settings:")
                        print("1: View current API key")
                        print("2: Delete API key")
                        print("3: Enter a new API key")
                        print("4: Return to main menu")
                    
                    choice = safe_input("Enter option [1-4]: ")
                    if choice is None:  # User cancelled
                        return saved_key
                    
                    if choice == "" or choice == "4":
                        return saved_key
                        
                    if choice == "1":
                        if COMPATIBLE_OUTPUT:
                            output.print(f"[blue]Saved API Key:[/blue] {output.escape(saved_key)}\n")
                        else:
                            print(f"Saved API Key: {saved_key}\n")
                    elif choice == "2":
                        if safe_file_delete(API_KEY_FILE):
                            if COMPATIBLE_OUTPUT:
                                print_status("Saved API key deleted.", "warning")
                            else:
                                print("Saved API key deleted.")
                            saved_key = None
                        else:
                            if COMPATIBLE_OUTPUT:
                                print_status("Could not delete API key file.", "warning")
                            else:
                                print("Could not delete API key file.")
                    elif choice == "3":
                        if COMPATIBLE_OUTPUT:
                            output.print("Enter your [blue]VirusTotal[/blue] API key (create an account at https://virustotal.com/gui/my-apikey), or press Enter to cancel:")
                        else:
                            print("Enter your VirusTotal API key (create an account at https://virustotal.com/gui/my-apikey), or press Enter to cancel:")
                        user_key = safe_input("")
                        if user_key is None:
                            if COMPATIBLE_OUTPUT:
                                print_status("No changes made to API key.", "warning")
                            else:
                                print("No changes made to API key.")
                        elif user_key:
                            if save_api_key(user_key):
                                if COMPATIBLE_OUTPUT:
                                    print_status("API key saved for future runs.", "success")
                                else:
                                    print("API key saved for future runs.")
                                saved_key = user_key
                            else:
                                if COMPATIBLE_OUTPUT:
                                    print_status("Failed to save API key.", "error")
                                else:
                                    print("Failed to save API key.")
                        else:
                            if COMPATIBLE_OUTPUT:
                                print_status("No changes made to API key.", "warning")
                            else:
                                print("No changes made to API key.")
                    else:
                        print("Invalid input. Please enter a number between 1 and 4.")
                except Exception as e:
                    if COMPATIBLE_OUTPUT:
                        print_status(f"Error in API menu: {e}", "error")
                    else:
                        print(f"Error in API menu: {e}")
                    continue
        else:
            if COMPATIBLE_OUTPUT:
                output.print("No VirusTotal API key saved.")
                output.print("Enter your [blue]VirusTotal[/blue] API key (create an account at https://virustotal.com/gui/my-apikey), or press Enter to skip:")
            else:
                print("No VirusTotal API key saved.")
                print("Enter your VirusTotal API key (create an account at https://virustotal.com/gui/my-apikey), or press Enter to skip:")
            user_key = safe_input("")
            if user_key is None:
                if COMPATIBLE_OUTPUT:
                    print_status("Continuing without VirusTotal API key. Reputation checks will be skipped.", "warning")
                else:
                    print("Continuing without VirusTotal API key. Reputation checks will be skipped.")
                return None
            elif user_key:
                if save_api_key(user_key):
                    if COMPATIBLE_OUTPUT:
                        print_status("API key saved for future runs.", "success")
                    else:
                        print("API key saved for future runs.")
                    return user_key
                else:
                    if COMPATIBLE_OUTPUT:
                        print_status("Failed to save API key. Continuing without it.", "error")
                    else:
                        print("Failed to save API key. Continuing without it.")
                    return None
            else:
                if COMPATIBLE_OUTPUT:
                    print_status("Continuing without VirusTotal API key. Reputation checks will be skipped.", "warning")
                else:
                    print("Continuing without VirusTotal API key. Reputation checks will be skipped.")
                return None
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error in API key management: {e}", "error")
            print_status("Continuing without API key changes.", "warning")
        else:
            print(f"Error in API key management: {e}")
            print("Continuing without API key changes.")
    
    return saved_key if 'saved_key' in locals() else None

def print_current_config(vt_api_key, output_mode):
    """Display current configuration status with error handling."""
    try:
        if COMPATIBLE_OUTPUT:
            config_parts = ["[magenta][Current configuration]:[/magenta] Running"]
            
            if vt_api_key:
                config_parts.append("[blue]with API key[/blue]")
            else:
                config_parts.append("[red]without API key[/red]")
            
            config_parts.append("and")
            
            if output_mode == "fanged":
                config_parts.append("[red]fanged[/red]")
            else:
                config_parts.append("[green]defanged[/green]")
            
            config_parts.append("output format.")
            
            output.print(" ".join(config_parts) + "\n")
        else:
            # Fallback for basic terminals
            api_status = "with API key" if vt_api_key else "without API key"
            print(f"Current configuration: Running {api_status} and {output_mode} output format.\n")
    except Exception as e:
        print(f"Configuration: API key {'set' if vt_api_key else 'not set'}, {output_mode} mode\n")

def run_analysis(file_path, vt_api_key):
    """Run complete email analysis with comprehensive error handling."""
    global last_url_analysis_results, last_received_hops, last_body_analysis_results, last_attachment_results
    global last_analyzed_file_path, last_analyzed_file_type, last_ip_analysis_results, last_header_analysis
    global last_analyzed_msg_obj
    
    try:
        # Reset previous results
        last_url_analysis_results = None
        last_received_hops = None
        last_body_analysis_results = None
        last_attachment_results = None
        last_ip_analysis_results = None
        last_header_analysis = None
        
        # Store analyzed file info for potential future use
        last_analyzed_file_path = file_path
        
        # Validate file path
        if not file_path or not file_path.strip():
            if COMPATIBLE_OUTPUT:
                print_status("Error: No file path provided.", "error")
            else:
                print("Error: No file path provided.")
            return
        
        file_path = file_path.strip()
        
        # Check if file exists
        if not os.path.exists(file_path):
            if COMPATIBLE_OUTPUT:
                print_status(f"Error: File '{file_path}' not found.", "error")
            else:
                print(f"Error: File '{file_path}' not found.")
            return
        
        # Check file size (warn about large files)
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # 100MB
                if COMPATIBLE_OUTPUT:
                    print_status(f"Warning: Large file detected ({file_size // (1024*1024)}MB). Processing may be slow.", "warning")
                else:
                    print(f"Warning: Large file detected ({file_size // (1024*1024)}MB). Processing may be slow.")
        except OSError:
            pass  # Continue if we can't get file size
        
        # Show defanging status if enabled
        try:
            if output_mode == "defanged":
                if COMPATIBLE_OUTPUT:
                    output.print("[blue bold]DEFANGED OUTPUT MODE:[/blue bold] [green]URLs and IPs are displayed in safe format[/green]")
                    output.print("")  # Use output.print for blank line
                else:
                    print("DEFANGED OUTPUT MODE: URLs and IPs are displayed in safe format")
                    print()
        except Exception:
            pass  # Non-critical display issue
        
        # Parse email file
        try:
            msg_obj, filetype = parser.load_email(file_path)
            last_analyzed_msg_obj = msg_obj
            last_analyzed_file_type = filetype  # Store file type
            print(f"Detected file type: {filetype}")
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error: Could not parse email file: {e}", "error")
                print_status("The file may be corrupted or in an unsupported format.", "warning")
            else:
                print(f"Error: Could not parse email file: {e}")
                print("The file may be corrupted or in an unsupported format.")
            return
        
        # Display subject
        try:
            subject = msg_obj.get('Subject', 'No Subject') if msg_obj else 'No Subject'
            if COMPATIBLE_OUTPUT:
                output.print(f"Subject: {output.escape(str(subject))}")
                output.print("")  # Use output.print for blank line
            else:
                print(f"Subject: {subject}")
                print()
        except Exception as e:
            print(f"Subject: [Unable to read - {e}]")
            print()

        # Header analysis with structured storage
        try:
            print_section_header("EMAIL HEADER ANALYSIS")
            # Store basic header analysis results
            last_header_analysis = {
                'malicious_factors': [],
                'warning_factors': [],
                'benign_factors': []
            }
            
            # Extract authentication results for structured storage
            try:
                auth_results = msg_obj.get('Authentication-Results', '').lower() if msg_obj else ''
                if 'spf=fail' in auth_results or 'spf=softfail' in auth_results:
                    last_header_analysis['malicious_factors'].append('SPF failure detected')
                elif 'spf=pass' in auth_results:
                    last_header_analysis['benign_factors'].append('SPF authentication passed')
                    
                if 'dkim=fail' in auth_results:
                    last_header_analysis['malicious_factors'].append('DKIM failure detected')
                elif 'dkim=pass' in auth_results:
                    last_header_analysis['benign_factors'].append('DKIM authentication passed')
                    
                if 'dmarc=fail' in auth_results:
                    last_header_analysis['malicious_factors'].append('DMARC failure detected')
                elif 'dmarc=pass' in auth_results:
                    last_header_analysis['benign_factors'].append('DMARC authentication passed')
                    
                # Check Reply-To presence
                reply_to = msg_obj.get('Reply-To', '') if msg_obj else ''
                if not reply_to or not reply_to.strip():
                    last_header_analysis['warning_factors'].append('Reply-To header missing')
                else:
                    last_header_analysis['benign_factors'].append('Reply-To header present')
                    
            except Exception:
                pass
            
            header_analyzer.analyze_headers(msg_obj)
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error during header analysis: {e}", "error")
                print_status("Skipping header analysis and continuing...", "warning")
            else:
                print(f"Error during header analysis: {e}")
                print("Skipping header analysis and continuing...")

        # IP analysis
        try:
            print_section_header("IP ADDRESS ANALYSIS")
            last_ip_analysis_results = ioc_extractor.analyze_ips(msg_obj, api_key=vt_api_key)
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error during IP analysis: {e}", "error")
                print_status("Skipping IP analysis and continuing...", "warning")
            else:
                print(f"Error during IP analysis: {e}")
                print("Skipping IP analysis and continuing...")

        # URL analysis
        try:
            print_section_header("URL ANALYSIS")
            last_url_analysis_results = url_extractor.analyze_urls(msg_obj, api_key=vt_api_key)
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error during URL analysis: {e}", "error")
                print_status("Skipping URL analysis and continuing...", "warning")
            else:
                print(f"Error during URL analysis: {e}")
                print("Skipping URL analysis and continuing...")

        # Body analysis - NEW SECTION
        try:
            print_section_header("EMAIL BODY ANALYSIS")
            last_body_analysis_results = body_analyzer.analyze_email_body(msg_obj, api_key=vt_api_key)
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error during body analysis: {e}", "error")
                print_status("Skipping body analysis and continuing...", "warning")
            else:
                print(f"Error during body analysis: {e}")
                print("Skipping body analysis and continuing...")

        # Attachment analysis
        try:
            print_section_header("ATTACHMENT ANALYSIS")
            attachment_results = attachment_analyzer.analyze_attachments(msg_obj, api_key=vt_api_key)
            if attachment_results:
                last_attachment_results = [att for att in attachment_results if att is not None and isinstance(att, dict)]
                print(f"Processed {len(last_attachment_results)} valid attachment(s) out of {len(attachment_results)} total.")
            else:
                last_attachment_results = []
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error during attachment analysis: {e}", "error")
                print_status("Skipping attachment analysis and continuing...", "warning")
            else:
                print(f"Error during attachment analysis: {e}")
                print("Skipping attachment analysis and continuing...")
            last_attachment_results = []
        
        if COMPATIBLE_OUTPUT:
            print_status("Analysis completed.", "success")
        else:
            print("Analysis completed.")
        
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user.")
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Unexpected error during analysis: {str(e)}", "error")
            print_status("Analysis could not be completed.", "warning")
        else:
            print(f"Unexpected error during analysis: {str(e)}")
            print("Analysis could not be completed.")

def handle_output_settings():
    """Handle output settings submenu with error handling."""
    global output_mode
    
    try:
        while True:
            try:
                if COMPATIBLE_OUTPUT:
                    output.print("\n[blue]Output Settings:[/blue]")
                else:
                    print("\nOutput Settings:")

                fanged_option = "[blue]1:[/blue] Fanged"
                defanged_option = "[blue]2:[/blue] Defanged"
                if output_mode == "fanged":
                    fanged_option += " ([red]current[/red])"
                elif output_mode == "defanged":
                    defanged_option += " ([green]current[/green])"

                if COMPATIBLE_OUTPUT:
                    output.print(fanged_option)
                    output.print(defanged_option)
                    output.print("[blue]3:[/blue] Return to main menu")
                else:
                    print("1: Fanged" + (" (current)" if output_mode == "fanged" else ""))
                    print("2: Defanged" + (" (current)" if output_mode == "defanged" else ""))
                    print("3: Return to main menu")

                submenu_choice = safe_input("Enter option [1-3]: ")
                if submenu_choice is None:  # User cancelled
                    break

                if submenu_choice == "1":
                    output_mode = "fanged"
                    if save_output_mode(output_mode):
                        if COMPATIBLE_OUTPUT:
                            output.print("Output mode set to [red]Fanged[/red] and saved.")
                        else:
                            print("Output mode set to Fanged and saved.")
                    else:
                        if COMPATIBLE_OUTPUT:
                            output.print("Output mode set to [red]Fanged[/red] but could not save setting.")
                        else:
                            print("Output mode set to Fanged but could not save setting.")
                    break
                elif submenu_choice == "2":
                    output_mode = "defanged"
                    if save_output_mode(output_mode):
                        if COMPATIBLE_OUTPUT:
                            output.print("Output mode set to [green]Defanged[/green] and saved.")
                        else:
                            print("Output mode set to Defanged and saved.")
                    else:
                        if COMPATIBLE_OUTPUT:
                            output.print("Output mode set to [green]Defanged[/green] but could not save setting.")
                        else:
                            print("Output mode set to Defanged but could not save setting.")
                    break
                elif submenu_choice == "3" or submenu_choice == "":
                    break
                else:
                    print("Invalid input. Please enter 1, 2, or 3.")
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error in output settings: {e}", "error")
                else:
                    print(f"Error in output settings: {e}")
                continue
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error in output settings menu: {e}", "error")
        else:
            print(f"Error in output settings menu: {e}")

def view_body_analysis_details():
    """Display detailed body analysis breakdown."""
    global last_body_analysis_results
    
    if not last_body_analysis_results:
        if COMPATIBLE_OUTPUT:
            print_status("No body analysis results available. Run an analysis first.", "warning")
        else:
            print("No body analysis results available. Run an analysis first.")
        return
    
    try:
        body_analyzer.display_detailed_body_analysis(last_body_analysis_results)
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error displaying body analysis details: {e}", "error")
        else:
            print(f"Error displaying body analysis details: {e}")

def view_received_hops():
    """Display detailed email routing hops."""
    global last_received_hops
    
    if not last_received_hops:
        if COMPATIBLE_OUTPUT:
            print_status("No received hops available. Run an analysis first.", "warning")
        else:
            print("No received hops available. Run an analysis first.")
        return
    
    try:
        print_section_header("EMAIL ROUTING HOPS")
        
        if COMPATIBLE_OUTPUT:
            output.print(f"Found [blue]{len(last_received_hops)}[/blue] routing hop{'s' if len(last_received_hops) != 1 else ''}:\n")
        else:
            print(f"Found {len(last_received_hops)} routing hop{'s' if len(last_received_hops) != 1 else ''}:\n")
        
        for hop in last_received_hops:
            try:
                index = hop.get('index', '?')
                content = hop.get('content', 'No content')
                
                # Content already has ANSI color codes - display directly
                if COMPATIBLE_OUTPUT:
                    # Create the blue hop number using output system, then combine with pre-colored content
                    hop_number = output.colorize(f"[{index}]", "blue")
                    print(f"{hop_number} {content}")  # Use regular print since content has ANSI codes
                else:
                    # For non-compatible terminals, strip all color codes
                    import re
                    clean_content = re.sub(r'\033\[[0-9;]*m', '', content)
                    print(f"[{index}] {clean_content}")
                    
            except Exception as e:
                print(f"  [?] Error displaying hop: {e}")
        
        # Summary
        if COMPATIBLE_OUTPUT:
            output.print(f"\nTotal: {len(last_received_hops)} hop{'s' if len(last_received_hops) != 1 else ''}")
        else:
            print(f"\nTotal: {len(last_received_hops)} hop{'s' if len(last_received_hops) != 1 else ''}")
        
        # Return prompt
        try:
            safe_input("\nPress Enter to return to main menu...")
        except:
            pass  # User pressed Ctrl+C or similar, just return
                
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error displaying hops: {e}", "error")
        else:
            print(f"Error displaying hops: {e}")

def view_url_findings():
    """Display comprehensive URL analysis from both email and attachments."""
    global last_url_analysis_results, last_attachment_results
    
    # Check if we have any URL data
    email_urls = last_url_analysis_results or []
    attachment_urls = []
    
    # Extract URL data from attachment results
    if last_attachment_results:
        for attachment in last_attachment_results:
            content_analysis = attachment.get('attachment_content_analysis', {})
            if content_analysis.get('url_analysis', {}).get('results'):
                attachment_urls.append({
                    'attachment_name': attachment.get('filename', 'unknown'),
                    'attachment_index': attachment.get('index', '?'),
                    'url_results': content_analysis['url_analysis']['results']
                })
    
    if not email_urls and not attachment_urls:
        if COMPATIBLE_OUTPUT:
            print_status("No URL analysis results available. Run an analysis first.", "warning")
        else:
            print("No URL analysis results available. Run an analysis first.")
        return
    
    try:
        print_section_header("URL FINDINGS")
        
        # SECTION 1: URLs from Email Body
        if email_urls:
            if COMPATIBLE_OUTPUT:
                output.print("[magenta]URLs FOUND IN EMAIL BODY[/magenta]\n")
            else:
                print("URLs FOUND IN EMAIL BODY\n")
            
            for i, result in enumerate(email_urls):
                if i > 0:
                    if COMPATIBLE_OUTPUT:
                        output.print("")
                    else:
                        print()
                
                domain = result['domain']
                urls = result['urls']
                verdict = result['verdict']
                
                # Apply defanging to domain
                display_domain = apply_defanging(domain)
                
                # Build and display the header with proper color handling
                if COMPATIBLE_OUTPUT:
                    escaped_domain = output.escape(display_domain)
                    
                    if verdict == "malicious":
                        verdict_colored = output.colorize("MALICIOUS", "red")
                    elif verdict == "suspicious":
                        verdict_colored = output.colorize("SUSPICIOUS", "orange3")
                    elif verdict == "benign":
                        verdict_colored = output.colorize("BENIGN", "green")
                    else:
                        verdict_colored = output.colorize("UNCHECKED", "orange3")
                    
                    header_text = f"{escaped_domain} - {verdict_colored} ({len(urls)} URL{'s' if len(urls) != 1 else ''}):"
                    print(header_text)
                else:
                    clean_verdict = verdict.upper()
                    print(f"{display_domain} - {clean_verdict} ({len(urls)} URL{'s' if len(urls) != 1 else ''}):")
                
                # Display each URL with defanging
                for j, url in enumerate(urls, 1):
                    display_url = apply_defanging(url)
                    escaped_url = output.escape(display_url) if COMPATIBLE_OUTPUT else display_url
                    
                    url_line = f"  {j:2}. {escaped_url}"
                    if COMPATIBLE_OUTPUT:
                        output.print(url_line)
                    else:
                        print(f"  {j:2}. {display_url}")
        
        # SECTION 2: URLs from Attachments
        if attachment_urls:
            if email_urls:
                if COMPATIBLE_OUTPUT:
                    output.print("\n")
                else:
                    print("\n")
            
            if COMPATIBLE_OUTPUT:
                output.print("[magenta]URLs FOUND IN ATTACHMENTS[/magenta]\n")
            else:
                print("URLs FOUND IN ATTACHMENTS\n")
            
            for attachment_data in attachment_urls:
                attachment_name = attachment_data['attachment_name']
                attachment_index = attachment_data['attachment_index']
                url_results = attachment_data['url_results']
                
                # Display attachment header
                display_attachment_name = apply_defanging(attachment_name)
                escaped_attachment_name = output.escape(display_attachment_name) if COMPATIBLE_OUTPUT else display_attachment_name
                
                if COMPATIBLE_OUTPUT:
                    output.print(f"[blue]From Attachment {attachment_index}: {escaped_attachment_name}[/blue]")
                else:
                    print(f"From Attachment {attachment_index}: {escaped_attachment_name}")
                
                # Display URL results for this attachment
                for i, result in enumerate(url_results):
                    if i > 0:
                        if COMPATIBLE_OUTPUT:
                            output.print("")
                        else:
                            print()
                    
                    domain = result['domain']
                    urls = result['urls']
                    verdict = result['verdict']
                    
                    # Apply defanging to domain
                    display_domain = apply_defanging(domain)
                    
                    # Build and display the header
                    if COMPATIBLE_OUTPUT:
                        escaped_domain = output.escape(display_domain)
                        
                        if verdict == "malicious":
                            verdict_colored = output.colorize("MALICIOUS", "red")
                        elif verdict == "suspicious":
                            verdict_colored = output.colorize("SUSPICIOUS", "orange3")
                        elif verdict == "benign":
                            verdict_colored = output.colorize("BENIGN", "green")
                        else:
                            verdict_colored = output.colorize("UNCHECKED", "orange3")
                        
                        header_text = f"  {escaped_domain} - {verdict_colored} ({len(urls)} URL{'s' if len(urls) != 1 else ''}):"
                        print(header_text)
                    else:
                        clean_verdict = verdict.upper()
                        print(f"  {display_domain} - {clean_verdict} ({len(urls)} URL{'s' if len(urls) != 1 else ''}):")
                    
                    # Display each URL
                    for j, url in enumerate(urls, 1):
                        display_url = apply_defanging(url)
                        escaped_url = output.escape(display_url) if COMPATIBLE_OUTPUT else display_url
                        
                        url_line = f"    {j:2}. {escaped_url}"
                        if COMPATIBLE_OUTPUT:
                            output.print(url_line)
                        else:
                            print(f"    {j:2}. {display_url}")
                
                if COMPATIBLE_OUTPUT:
                    output.print("")  # Blank line between attachments
                else:
                    print()
        
        # SUMMARY
        email_url_count = sum(len(r['urls']) for r in email_urls) if email_urls else 0
        email_domain_count = len(email_urls) if email_urls else 0
        
        attachment_url_count = 0
        attachment_domain_count = 0
        if attachment_urls:
            for attachment_data in attachment_urls:
                url_results = attachment_data['url_results']
                attachment_url_count += sum(len(r['urls']) for r in url_results)
                attachment_domain_count += len(url_results)
        
        total_urls = email_url_count + attachment_url_count
        total_domains = email_domain_count + attachment_domain_count
        
        if COMPATIBLE_OUTPUT:
            output.print(f"\n[blue]SUMMARY:[/blue]")
            if email_urls:
                output.print(f"Email body: {email_url_count} URL{'s' if email_url_count != 1 else ''} across {email_domain_count} domain{'s' if email_domain_count != 1 else ''}")
            if attachment_urls:
                attachment_count = len(attachment_urls)
                output.print(f"Attachments: {attachment_url_count} URL{'s' if attachment_url_count != 1 else ''} across {attachment_domain_count} domain{'s' if attachment_domain_count != 1 else ''} in {attachment_count} file{'s' if attachment_count != 1 else ''}")
            output.print(f"Total: {total_urls} URL{'s' if total_urls != 1 else ''} across {total_domains} domain{'s' if total_domains != 1 else ''}")
        else:
            print(f"\nSUMMARY:")
            if email_urls:
                print(f"Email body: {email_url_count} URL{'s' if email_url_count != 1 else ''} across {email_domain_count} domain{'s' if email_domain_count != 1 else ''}")
            if attachment_urls:
                attachment_count = len(attachment_urls)
                print(f"Attachments: {attachment_url_count} URL{'s' if attachment_url_count != 1 else ''} across {attachment_domain_count} domain{'s' if attachment_domain_count != 1 else ''} in {attachment_count} file{'s' if attachment_count != 1 else ''}")
            print(f"Total: {total_urls} URL{'s' if total_urls != 1 else ''} across {total_domains} domain{'s' if total_domains != 1 else ''}")
        
        # Return prompt
        try:
            safe_input("\nPress Enter to return to main menu...")
        except:
            pass
                
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error displaying URL findings: {e}", "error")
        else:
            print(f"Error displaying URL findings: {e}")

def apply_defanging_for_findings(text):
    """Apply defanging to text if defang mode is enabled - for executive findings"""
    try:
        if defanger.should_defang():
            return defanger.defang_text(str(text))
        else:
            return str(text)
    except Exception:
        return str(text)

def compile_comprehensive_findings():
    """Compile ALL significant findings from all analysis modules for report-ready output"""
    global last_url_analysis_results, last_body_analysis_results, last_attachment_results
    
    findings = {
        'critical_threats': [],
        'high_risk_indicators': [],
        'suspicious_activity': [],
        'manual_verification_required': [],
        'authentication_infrastructure_concerns': [],
        'malicious_iocs': [],
        'total_iocs': 0
    }

    # FIXED: Comprehensive None and type checking
    url_results = last_url_analysis_results if (last_url_analysis_results is not None and isinstance(last_url_analysis_results, list)) else []
    body_results = last_body_analysis_results if (last_body_analysis_results is not None and isinstance(last_body_analysis_results, dict)) else {}
    attachment_results = last_attachment_results if (last_attachment_results is not None and isinstance(last_attachment_results, list)) else []

    # Header Analysis - Enhanced to capture all authentication issues
    try:
        import sys
        main_module = sys.modules.get('__main__') or sys.modules.get('phishalyzer')
        if main_module and hasattr(main_module, 'last_header_analysis'):
            header_analysis = getattr(main_module, 'last_header_analysis', {})
            if isinstance(header_analysis, dict):
                malicious_factors = header_analysis.get('malicious_factors', [])
                warning_factors = header_analysis.get('warning_factors', [])
                
                if malicious_factors and isinstance(malicious_factors, list):
                    findings['high_risk_indicators'].extend([f"Email authentication failure: {factor}" for factor in malicious_factors])
                if warning_factors and isinstance(warning_factors, list):
                    findings['authentication_infrastructure_concerns'].extend([f"Authentication concern: {factor}" for factor in warning_factors])
        else:
            # Default authentication analysis if no structured data available
            findings['high_risk_indicators'].extend([
                "Email authentication failure: SPF missing or failed",
                "Email authentication failure: DKIM missing or failed", 
                "Email authentication failure: DMARC missing or failed"
            ])
            findings['authentication_infrastructure_concerns'].append("Authentication verification: Reply-To header missing")
    except Exception as e:
        print(f"Warning: Error processing header analysis: {e}")

    # IP Analysis - Enhanced categorization
    try:
        if main_module and hasattr(main_module, 'last_ip_analysis_results'):
            ip_results = getattr(main_module, 'last_ip_analysis_results', [])
            if isinstance(ip_results, list):
                for ip_data in ip_results:
                    if ip_data and isinstance(ip_data, (list, tuple)) and len(ip_data) >= 3:
                        ip, country, verdict = ip_data[:3]
                        comment = ip_data[3] if len(ip_data) > 3 else ""
                        
                        if verdict == 'malicious':
                            findings['critical_threats'].append(f"Malicious IP address detected: {apply_defanging_for_findings(ip)} ({country}) - {comment}")
                            findings['malicious_iocs'].append(f"IP: {apply_defanging_for_findings(ip)}")
                            findings['total_iocs'] += 1
                        elif verdict == 'suspicious':
                            findings['suspicious_activity'].append(f"Suspicious IP address detected: {apply_defanging_for_findings(ip)} ({country}) - {comment}")
                        elif verdict == 'unchecked' and country != 'Private':
                            findings['manual_verification_required'].append(f"Unchecked IP address: {apply_defanging_for_findings(ip)} ({country}) - Manual investigation required")
    except Exception as e:
        print(f"Warning: Error processing IP analysis: {e}")
    
    # URL Analysis - Enhanced with detailed breakdown
    if url_results:
        try:
            for result in url_results:
                if result and isinstance(result, dict):
                    domain = result.get('domain', 'unknown')
                    verdict = result.get('verdict', 'unknown')
                    url_count = result.get('url_count', len(result.get('urls', [])))
                    comment = result.get('comment', '')
                    
                    if verdict == 'malicious':
                        findings['critical_threats'].append(
                            f"Malicious domain detected: {apply_defanging_for_findings(domain)} ({url_count} URL{'s' if url_count != 1 else ''}) - {comment}"
                        )
                        findings['malicious_iocs'].append(f"Domain: {apply_defanging_for_findings(domain)}")
                        findings['total_iocs'] += 1
                    elif verdict == 'suspicious':
                        findings['suspicious_activity'].append(
                            f"Suspicious domain detected: {apply_defanging_for_findings(domain)} ({url_count} URL{'s' if url_count != 1 else ''}) - {comment}"
                        )
                    elif verdict == 'unchecked':
                        if domain not in ['malformed-urls', 'truncated-urls', 'unknown']:
                            findings['manual_verification_required'].append(
                                f"Unchecked domain not in threat database: {apply_defanging_for_findings(domain)} ({url_count} URL{'s' if url_count != 1 else ''}) - Manual investigation required"
                            )
                        else:
                            findings['manual_verification_required'].append(
                                f"Malformed URLs detected requiring manual inspection ({url_count} URL{'s' if url_count != 1 else ''})"
                            )
        except Exception as e:
            print(f"Warning: Error processing URL analysis: {e}")
    
    # Body Analysis - Enhanced phishing content categorization
    if body_results:
        try:
            body_findings = body_results.get('findings', {})
            risk_score = body_results.get('risk_score', 0)
            
            if body_findings and isinstance(body_findings, dict):
                critical_categories = []
                high_risk_categories = []
                medium_risk_categories = []
                
                for finding_key, finding_data in body_findings.items():
                    if isinstance(finding_data, dict):
                        risk_level = finding_data.get('risk_level')
                        name = finding_data.get('name')
                        keyword_count = finding_data.get('keyword_count', 0)
                        
                        if risk_level == 'HIGH':
                            if any(keyword in name.lower() for keyword in ['credential', 'payment', 'executive', 'malware']):
                                critical_categories.append(f"{name} ({keyword_count} indicators)")
                            else:
                                high_risk_categories.append(f"{name} ({keyword_count} indicators)")
                        elif risk_level == 'MEDIUM':
                            medium_risk_categories.append(f"{name} ({keyword_count} indicators)")
                
                if critical_categories:
                    findings['critical_threats'].append(f"Critical phishing content detected: {', '.join(critical_categories)}")
                if high_risk_categories:
                    findings['high_risk_indicators'].append(f"High-risk phishing content: {', '.join(high_risk_categories)}")
                if medium_risk_categories:
                    findings['suspicious_activity'].append(f"Medium-risk phishing patterns: {', '.join(medium_risk_categories)}")
        except Exception as e:
            print(f"Warning: Error processing body analysis: {e}")
    
    # Attachment Analysis - Comprehensive threat categorization with debugging
    if attachment_results:
        try:
            # Enhanced filtering and debugging
            all_attachments = [a for a in attachment_results if a is not None]
            valid_attachments = [a for a in all_attachments if isinstance(a, dict)]
            
            if valid_attachments:
                # Process ALL attachments regardless of their current categorization
                for att in valid_attachments:
                    filename = att.get('filename', 'unknown')
                    vt_verdict = att.get('vt_verdict', 'unknown')
                    vt_comment = att.get('vt_comment', '')
                    threat_level = att.get('threat_level', 'low')
                    is_spoofed = att.get('is_spoofed', False)
                    spoof_description = att.get('spoof_description', '')
                    
                    # CRITICAL THREATS
                    if threat_level == 'critical':
                        findings['critical_threats'].append(
                            f"Critical file threat detected: {filename} - {spoof_description or 'Malicious file disguised with deceptive extension'}"
                        )
                    elif vt_verdict == 'malicious':
                        findings['critical_threats'].append(
                            f"Malicious file confirmed by threat intelligence: {filename} - {vt_comment or 'Multiple vendors flagged as malicious'}"
                        )
                        findings['malicious_iocs'].append(f"File: {filename}")
                        findings['total_iocs'] += 1
                    
                    # HIGH RISK INDICATORS
                    elif threat_level == 'high' and is_spoofed:
                        findings['high_risk_indicators'].append(
                            f"High-risk file spoofing detected: {filename} - {spoof_description or 'Suspicious file extension mismatch'}"
                        )
                    elif vt_verdict == 'suspicious':
                        findings['suspicious_activity'].append(
                            f"Suspicious file flagged by threat intelligence: {filename} - {vt_comment or 'Flagged as suspicious'}"
                        )
                    
                    # MEDIUM RISK / SUSPICIOUS
                    elif threat_level == 'medium' and is_spoofed:
                        findings['suspicious_activity'].append(
                            f"File extension mismatch detected: {filename} - {spoof_description or 'File type inconsistency'}"
                        )
                    
                    # MANUAL VERIFICATION REQUIRED
                    elif vt_verdict in ['unknown', 'unchecked']:
                        reason = "File not in threat intelligence database"
                        if att.get('size', 0) == 0:
                            reason = "Empty file or extraction failed"
                        elif 'password' in filename.lower() or 'encrypted' in filename.lower():
                            reason = "Password protection prevents analysis"
                        elif vt_verdict == 'unchecked':
                            reason = "File hash will need to be investigated manually"
                        
                        findings['manual_verification_required'].append(
                            f"Unchecked attachment: {filename} - {reason}"
                        )
                            
        except Exception as e:
            print(f"Warning: Error processing attachment analysis: {e}")
    
    return findings

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

def generate_zendesk_report():
    """Generate a comprehensive Zendesk-ready report of the email analysis."""
    global last_url_analysis_results, last_received_hops, last_body_analysis_results
    global last_attachment_results, last_analyzed_file_path, last_analyzed_file_type
    global last_ip_analysis_results, last_header_analysis
    
    # Check if any analysis has been run
    if not any([last_url_analysis_results, last_body_analysis_results, last_attachment_results, 
                last_ip_analysis_results, last_received_hops]):
        if COMPATIBLE_OUTPUT:
            print_status("No analysis results available. Run an analysis first.", "warning")
        else:
            print("No analysis results available. Run an analysis first.")
        return
    
    try:
        # Generate filename
        current_date = datetime.now().strftime("%m.%d.%Y")
        filename = f"email_analysis_{current_date}.txt"
        desktop_path = get_desktop_path()
        file_path = os.path.join(desktop_path, filename)
        
        # Build report content
        report_lines = []
        
        # Email Header Section
        report_lines.append("# Email Analysis Report")
        report_lines.append("")
        
        # File Information
        if last_analyzed_file_path:
            file_name = os.path.basename(last_analyzed_file_path)
            try:
                file_size = os.path.getsize(last_analyzed_file_path)
                size_str = f"{file_size:,} bytes"
                if file_size > 1024:
                    size_str += f" ({file_size / 1024:.1f} KB)"
                if file_size > 1024 * 1024:
                    size_str += f" ({file_size / (1024 * 1024):.1f} MB)"
            except:
                size_str = "Unknown"
            
            file_type = last_analyzed_file_type or "Unknown"
            
            report_lines.append("## Email File Information")
            report_lines.append(f"**Filename:** {file_name}")
            report_lines.append(f"**File Type:** {file_type}")
            report_lines.append(f"**File Size:** {size_str}")
            report_lines.append("")
        
        # Get comprehensive findings for verdict
        comprehensive_findings = compile_comprehensive_findings()
        verdict, reasons = determine_final_verdict(comprehensive_findings)
        
        # Extract one-word verdict
        if "CRITICAL" in verdict:
            one_word_verdict = "Malicious"
        elif "HIGH" in verdict:
            one_word_verdict = "Suspicious"
        elif "MEDIUM" in verdict or "LOW-MEDIUM" in verdict:
            one_word_verdict = "Suspicious"
        else:
            one_word_verdict = "Benign"
        
        # Verdict Section
        report_lines.append("## Security Verdict")
        report_lines.append(f"**Classification:** {one_word_verdict}")
        report_lines.append("")
        report_lines.append("**Supporting Analysis:**")
        for reason in reasons:
            report_lines.append(f"- {reason}")
        report_lines.append("")
        
        # Header Analysis Section
        report_lines.append("## Email Header Analysis")
        
        # Authentication Results
        auth_issues = []
        auth_passes = []
        if last_header_analysis and isinstance(last_header_analysis, dict):
            malicious_factors = last_header_analysis.get('malicious_factors', [])
            warning_factors = last_header_analysis.get('warning_factors', [])
            benign_factors = last_header_analysis.get('benign_factors', [])
            
            auth_issues.extend(malicious_factors)
            auth_issues.extend(warning_factors)
            auth_passes.extend(benign_factors)
        
        if auth_issues:
            report_lines.append("**Authentication Issues:**")
            for issue in auth_issues:
                report_lines.append(f"- {issue}")
            report_lines.append("")
        
        if auth_passes:
            report_lines.append("**Authentication Successes:**")
            for success in auth_passes:
                report_lines.append(f"- {success}")
            report_lines.append("")
        
        # Email Routing (if available)
        if last_received_hops and isinstance(last_received_hops, list):
            report_lines.append("**Email Routing:**")
            report_lines.append(f"- {len(last_received_hops)} routing hop{'s' if len(last_received_hops) != 1 else ''} identified")
            
            # Show first few hops with IPs highlighted
            for i, hop in enumerate(last_received_hops[:3]):
                raw_content = hop.get('raw', hop.get('content', ''))
                # Extract IPs from hop content
                import re
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_content)
                if ips:
                    # Apply defanging if needed
                    display_ips = []
                    for ip in ips[:2]:  # Show first 2 IPs
                        if output_mode == "defanged":
                            display_ips.append(apply_defanging_for_findings(ip))
                        else:
                            display_ips.append(ip)
                    report_lines.append(f"  - Hop {i+1}: {', '.join(display_ips)}")
            
            if len(last_received_hops) > 3:
                report_lines.append(f"  - ... and {len(last_received_hops) - 3} additional hops")
            report_lines.append("")
        
        # IP Analysis Section
        if last_ip_analysis_results and isinstance(last_ip_analysis_results, list):
            report_lines.append("## IP Address Analysis")
            
            malicious_ips = []
            suspicious_ips = []
            unchecked_ips = []
            benign_ips = []
            
            for ip_data in last_ip_analysis_results:
                if ip_data and isinstance(ip_data, (list, tuple)) and len(ip_data) >= 3:
                    ip, country, verdict = ip_data[:3]
                    comment = ip_data[3] if len(ip_data) > 3 else ""
                    
                    # Apply defanging if needed
                    display_ip = apply_defanging_for_findings(ip) if output_mode == "defanged" else ip
                    
                    if verdict == 'malicious':
                        malicious_ips.append(f"{display_ip} ({country}) - {comment}")
                    elif verdict == 'suspicious':
                        suspicious_ips.append(f"{display_ip} ({country}) - {comment}")
                    elif verdict == 'unchecked' and country != 'Private':
                        unchecked_ips.append(f"{display_ip} ({country})")
                    elif verdict == 'benign':
                        benign_ips.append(f"{display_ip} ({country})")
            
            if malicious_ips:
                report_lines.append("**Malicious IP Addresses:**")
                for ip_info in malicious_ips:
                    report_lines.append(f"- {ip_info}")
                report_lines.append("")
            
            if suspicious_ips:
                report_lines.append("**Suspicious IP Addresses:**")
                for ip_info in suspicious_ips:
                    report_lines.append(f"- {ip_info}")
                report_lines.append("")
            
            if unchecked_ips:
                report_lines.append("**Unchecked IP Addresses:**")
                for ip_info in unchecked_ips:
                    report_lines.append(f"- {ip_info}")
                report_lines.append("")
            
            if benign_ips:
                report_lines.append("**Benign IP Addresses:**")
                for ip_info in benign_ips:
                    report_lines.append(f"- {ip_info}")
                report_lines.append("")
        
        # URL Analysis Section
        email_urls = last_url_analysis_results or []
        attachment_urls = []
        
        # Extract URL data from attachment results
        if last_attachment_results:
            for attachment in last_attachment_results:
                if attachment and isinstance(attachment, dict):
                    content_analysis = attachment.get('attachment_content_analysis', {})
                    if content_analysis.get('url_analysis', {}).get('results'):
                        attachment_urls.append({
                            'attachment_name': attachment.get('filename', 'unknown'),
                            'attachment_index': attachment.get('index', '?'),
                            'url_results': content_analysis['url_analysis']['results']
                        })
        
        if email_urls or attachment_urls:
            report_lines.append("## URL Analysis")
            
            # Email URLs
            if email_urls:
                report_lines.append("**URLs from Email Body:**")
                
                for result in email_urls:
                    if result and isinstance(result, dict):
                        domain = result.get('domain', 'unknown')
                        verdict = result.get('verdict', 'unknown')
                        url_count = result.get('url_count', len(result.get('urls', [])))
                        urls = result.get('urls', [])
                        
                        # Apply defanging if needed
                        display_domain = apply_defanging_for_findings(domain) if output_mode == "defanged" else domain
                        
                        report_lines.append(f"- **{display_domain}** ({verdict.upper()}) - {url_count} URL{'s' if url_count != 1 else ''}")
                        
                        # Show sample URLs
                        for url in urls[:2]:  # Show first 2 URLs
                            display_url = apply_defanging_for_findings(url) if output_mode == "defanged" else url
                            report_lines.append(f"  - {display_url}")
                        if len(urls) > 2:
                            report_lines.append(f"  - ... and {len(urls) - 2} more")
                
                report_lines.append("")
            
            # Attachment URLs
            if attachment_urls:
                report_lines.append("**URLs from Attachments:**")
                
                for attachment_data in attachment_urls:
                    attachment_name = attachment_data['attachment_name']
                    url_results = attachment_data['url_results']
                    
                    display_attachment_name = apply_defanging_for_findings(attachment_name) if output_mode == "defanged" else attachment_name
                    report_lines.append(f"- **From {display_attachment_name}:**")
                    
                    for result in url_results:
                        domain = result['domain']
                        verdict = result['verdict']
                        url_count = len(result['urls'])
                        
                        display_domain = apply_defanging_for_findings(domain) if output_mode == "defanged" else domain
                        report_lines.append(f"  - {display_domain} ({verdict.upper()}) - {url_count} URL{'s' if url_count != 1 else ''}")
                
                report_lines.append("")
        
        # Email Body Analysis Section
        if last_body_analysis_results and isinstance(last_body_analysis_results, dict):
            findings = last_body_analysis_results.get('findings', {})
            risk_score = last_body_analysis_results.get('risk_score', 0)
            
            if findings:
                report_lines.append("## Email Body Analysis")
                report_lines.append(f"**Content Risk Score:** {risk_score}/100")
                report_lines.append("")
                
                # Group by risk level
                high_risk_findings = []
                medium_risk_findings = []
                low_risk_findings = []
                
                for finding_key, finding_data in findings.items():
                    if isinstance(finding_data, dict):
                        risk_level = finding_data.get('risk_level')
                        name = finding_data.get('name')
                        keyword_count = finding_data.get('keyword_count', 0)
                        
                        if risk_level == 'HIGH':
                            high_risk_findings.append(f"{name} ({keyword_count} indicators)")
                        elif risk_level == 'MEDIUM':
                            medium_risk_findings.append(f"{name} ({keyword_count} indicators)")
                        elif risk_level == 'LOW':
                            low_risk_findings.append(f"{name} ({keyword_count} indicators)")
                
                if high_risk_findings:
                    report_lines.append("**High Risk Content:**")
                    for finding in high_risk_findings:
                        report_lines.append(f"- {finding}")
                    report_lines.append("")
                
                if medium_risk_findings:
                    report_lines.append("**Medium Risk Content:**")
                    for finding in medium_risk_findings:
                        report_lines.append(f"- {finding}")
                    report_lines.append("")
                
                if low_risk_findings:
                    report_lines.append("**Low Risk Content:**")
                    for finding in low_risk_findings:
                        report_lines.append(f"- {finding}")
                    report_lines.append("")
        
        # Attachment Analysis Section
        if last_attachment_results and isinstance(last_attachment_results, list):
            valid_attachments = [a for a in last_attachment_results if a is not None and isinstance(a, dict)]
            
            if valid_attachments:
                report_lines.append("## Attachment Analysis")
                
                critical_attachments = []
                high_risk_attachments = []
                medium_risk_attachments = []
                benign_attachments = []
                
                for att in valid_attachments:
                    filename = att.get('filename', 'unknown')
                    threat_level = att.get('threat_level', 'low')
                    vt_verdict = att.get('vt_verdict', 'unknown')
                    vt_comment = att.get('vt_comment', '')
                    is_spoofed = att.get('is_spoofed', False)
                    spoof_description = att.get('spoof_description', '')
                    size = att.get('size', 0)
                    file_hash = att.get('hash', 'N/A')
                    
                    # Format size
                    size_str = f"{size:,} bytes" if size > 0 else "0 bytes"
                    
                    attachment_info = f"**{filename}** ({size_str})"
                    
                    if file_hash != "N/A":
                        attachment_info += f" - SHA256: {file_hash[:16]}..."
                    
                    if threat_level == 'critical' or vt_verdict == 'malicious':
                        if threat_level == 'critical':
                            attachment_info += f" - {spoof_description}"
                        else:
                            attachment_info += f" - {vt_comment}"
                        critical_attachments.append(attachment_info)
                    elif threat_level == 'high' or vt_verdict == 'suspicious':
                        if is_spoofed:
                            attachment_info += f" - {spoof_description}"
                        else:
                            attachment_info += f" - {vt_comment}"
                        high_risk_attachments.append(attachment_info)
                    elif threat_level == 'medium' or is_spoofed:
                        attachment_info += f" - {spoof_description or 'File type inconsistency'}"
                        medium_risk_attachments.append(attachment_info)
                    else:
                        if vt_verdict == 'benign':
                            attachment_info += f" - {vt_comment}"
                        elif vt_verdict in ['unknown', 'unchecked']:
                            attachment_info += " - Not found in threat database"
                        benign_attachments.append(attachment_info)
                
                if critical_attachments:
                    report_lines.append("**Critical Threat Attachments:**")
                    for att_info in critical_attachments:
                        report_lines.append(f"- {att_info}")
                    report_lines.append("")
                
                if high_risk_attachments:
                    report_lines.append("**High Risk Attachments:**")
                    for att_info in high_risk_attachments:
                        report_lines.append(f"- {att_info}")
                    report_lines.append("")
                
                if medium_risk_attachments:
                    report_lines.append("**Medium Risk Attachments:**")
                    for att_info in medium_risk_attachments:
                        report_lines.append(f"- {att_info}")
                    report_lines.append("")
                
                if benign_attachments:
                    report_lines.append("**Other Attachments:**")
                    for att_info in benign_attachments:
                        report_lines.append(f"- {att_info}")
                    report_lines.append("")
        
        # Footer
        report_lines.append("---")
        report_lines.append(f"*Report generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}*")
        report_lines.append(f"*Analysis tool: Phishalyzer*")
        
        # Write report to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
        
        if COMPATIBLE_OUTPUT:
            print_status(f"Report generated successfully: {file_path}", "success")
        else:
            print(f"Report generated successfully: {file_path}")
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error generating report: {e}", "error")
        else:
            print(f"Error generating report: {e}")

def determine_final_verdict(comprehensive_findings):
    """Determine final verdict based on comprehensive findings"""
    
    # Count different types of threats
    critical_count = len(comprehensive_findings['critical_threats'])
    malicious_ioc_count = len(comprehensive_findings['malicious_iocs'])
    high_risk_count = len(comprehensive_findings['high_risk_indicators'])
    suspicious_count = len(comprehensive_findings['suspicious_activity'])
    manual_verification_count = len(comprehensive_findings['manual_verification_required'])
    auth_concerns_count = len(comprehensive_findings['authentication_infrastructure_concerns'])
    
    # Determine verdict and supporting reasons
    if critical_count > 0 or malicious_ioc_count > 0:
        verdict = "CRITICAL RISK EMAIL"
        reasons = []
        
        if malicious_ioc_count > 0:
            reasons.append(f"Contains {malicious_ioc_count} confirmed malicious indicator{'s' if malicious_ioc_count != 1 else ''} from threat intelligence")
        if critical_count > 0:
            reasons.append("Exhibits critical security threats requiring immediate action")
        if high_risk_count > 0:
            reasons.append("Multiple high-risk phishing indicators detected")
        if suspicious_count > 0:
            reasons.append("Additional suspicious characteristics identified")
        if manual_verification_count > 0:
            reasons.append("Contains elements requiring manual security verification")
        if auth_concerns_count > 0:
            reasons.append("Email authentication mechanisms compromised or missing")
            
    elif high_risk_count >= 3 or (high_risk_count >= 1 and suspicious_count >= 2):
        verdict = "HIGH RISK EMAIL"
        reasons = []
        
        if high_risk_count > 0:
            reasons.append(f"Contains {high_risk_count} high-risk security indicator{'s' if high_risk_count != 1 else ''}")
        if suspicious_count > 0:
            reasons.append(f"Exhibits {suspicious_count} suspicious characteristic{'s' if suspicious_count != 1 else ''}")
        if manual_verification_count > 0:
            reasons.append("Multiple elements require manual investigation")
        if auth_concerns_count > 0:
            reasons.append("Email authentication issues detected")
            
    elif high_risk_count > 0 or suspicious_count >= 2:
        verdict = "MEDIUM RISK EMAIL"
        reasons = []
        
        if high_risk_count > 0:
            reasons.append("Contains security indicators requiring attention")
        if suspicious_count > 0:
            reasons.append("Exhibits suspicious patterns consistent with phishing attempts")
        if manual_verification_count > 0:
            reasons.append("Some elements could not be automatically verified")
        if auth_concerns_count > 0:
            reasons.append("Email authentication configuration has gaps")
            
    elif suspicious_count > 0 or manual_verification_count >= 3 or auth_concerns_count >= 2:
        verdict = "LOW-MEDIUM RISK EMAIL"
        reasons = []
        
        if suspicious_count > 0:
            reasons.append("Minor suspicious characteristics detected")
        if manual_verification_count > 0:
            reasons.append("Several elements require manual verification")
        if auth_concerns_count > 0:
            reasons.append("Email authentication could be improved")
            
    else:
        verdict = "LOW RISK EMAIL"
        reasons = ["No significant security threats identified through automated analysis"]
        if manual_verification_count > 0:
            reasons.append("Routine manual verification recommended")
    
    return verdict, reasons

def display_comprehensive_executive_summary(comprehensive_findings):
    """Display the comprehensive, report-ready executive summary"""
    print_section_header("EXECUTIVE FINDINGS REPORT")
    
    # Critical Threats Section
    if comprehensive_findings['critical_threats']:
        if COMPATIBLE_OUTPUT:
            output.print("[red bold]CRITICAL SECURITY THREATS:[/red bold]")
        else:
            print("CRITICAL SECURITY THREATS:")
        for threat in comprehensive_findings['critical_threats']:
            escaped_threat = output.escape(threat) if COMPATIBLE_OUTPUT else threat
            print(f"- {escaped_threat}")
        print()
    
    # High Risk Indicators Section
    if comprehensive_findings['high_risk_indicators']:
        if COMPATIBLE_OUTPUT:
            output.print("[red]HIGH RISK INDICATORS:[/red]")
        else:
            print("HIGH RISK INDICATORS:")
        for indicator in comprehensive_findings['high_risk_indicators']:
            escaped_indicator = output.escape(indicator) if COMPATIBLE_OUTPUT else indicator
            print(f"- {escaped_indicator}")
        print()
    
    # Suspicious Activity Section
    if comprehensive_findings['suspicious_activity']:
        if COMPATIBLE_OUTPUT:
            output.print("[orange3]SUSPICIOUS ACTIVITY:[/orange3]")
        else:
            print("SUSPICIOUS ACTIVITY:")
        for activity in comprehensive_findings['suspicious_activity']:
            escaped_activity = output.escape(activity) if COMPATIBLE_OUTPUT else activity
            print(f"- {escaped_activity}")
        print()
    
    # Manual Verification Required Section
    if comprehensive_findings['manual_verification_required']:
        if COMPATIBLE_OUTPUT:
            output.print("[yellow]ITEMS REQUIRING MANUAL VERIFICATION:[/yellow]")
        else:
            print("ITEMS REQUIRING MANUAL VERIFICATION:")
        for item in comprehensive_findings['manual_verification_required']:
            escaped_item = output.escape(item) if COMPATIBLE_OUTPUT else item
            print(f"- {escaped_item}")
        print()
    
    # Authentication & Infrastructure Concerns Section
    if comprehensive_findings['authentication_infrastructure_concerns']:
        if COMPATIBLE_OUTPUT:
            output.print("[orange3]AUTHENTICATION & INFRASTRUCTURE CONCERNS:[/orange3]")
        else:
            print("AUTHENTICATION & INFRASTRUCTURE CONCERNS:")
        for concern in comprehensive_findings['authentication_infrastructure_concerns']:
            escaped_concern = output.escape(concern) if COMPATIBLE_OUTPUT else concern
            print(f"- {escaped_concern}")
        print()
    
    # Final Verdict Section
    verdict, reasons = determine_final_verdict(comprehensive_findings)
    
    # Color the verdict based on risk level
    if "CRITICAL" in verdict:
        verdict_color = "red bold"
    elif "HIGH" in verdict:
        verdict_color = "red"
    elif "MEDIUM" in verdict:
        verdict_color = "orange3"
    else:
        verdict_color = "yellow"
    
    if COMPATIBLE_OUTPUT:
        output.print(f"[blue bold]FINAL VERDICT:[/blue bold] [{verdict_color}]{verdict}[/{verdict_color}]")
    else:
        print(f"FINAL VERDICT: {verdict}")

    for reason in reasons:
        escaped_reason = output.escape(reason) if COMPATIBLE_OUTPUT else reason
        print(f"- {escaped_reason}")
    
    # Show nothing found message only if truly nothing was found
    total_findings = (len(comprehensive_findings['critical_threats']) + 
                     len(comprehensive_findings['high_risk_indicators']) + 
                     len(comprehensive_findings['suspicious_activity']) + 
                     len(comprehensive_findings['manual_verification_required']) + 
                     len(comprehensive_findings['authentication_infrastructure_concerns']))
    
    if total_findings == 0:
        if COMPATIBLE_OUTPUT:
            output.print("\n[green]No significant security concerns identified in automated analysis.[/green]")
            output.print("[green]Email appears to be legitimate based on available threat intelligence.[/green]")
        else:
            print("\nNo significant security concerns identified in automated analysis.")
            print("Email appears to be legitimate based on available threat intelligence.")
    
    # Return prompt
    try:
        safe_input("\nPress Enter to return to main menu...")
    except:
        pass

def generate_comprehensive_executive_summary():
    """Generate comprehensive executive summary of all analysis findings"""
    global last_url_analysis_results, last_body_analysis_results, last_attachment_results
    
    # Check if any analysis has been run
    if not any([last_url_analysis_results, last_body_analysis_results, last_attachment_results]):
        if COMPATIBLE_OUTPUT:
            print_status("No analysis results available. Run an analysis first.", "warning")
        else:
            print("No analysis results available. Run an analysis first.")
        return
    
    try:
        # Compile comprehensive findings
        comprehensive_findings = compile_comprehensive_findings()
        
        # Display the comprehensive summary
        display_comprehensive_executive_summary(comprehensive_findings)
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error generating comprehensive executive summary: {e}", "error")
        else:
            print(f"Error generating comprehensive executive summary: {e}")

def generate_comprehensive_report():
    """Generate a comprehensive plaintext report of all analysis results."""
    global last_url_analysis_results, last_body_analysis_results, last_attachment_results
    global last_ip_analysis_results, last_received_hops, last_header_analysis
    global last_analyzed_file_path, last_analyzed_file_type, output_mode
    
    # Check if any analysis has been run
    if not any([last_url_analysis_results, last_body_analysis_results, last_attachment_results, 
                last_ip_analysis_results, last_received_hops]):
        if COMPATIBLE_OUTPUT:
            print_status("No analysis results available. Run an analysis first.", "warning")
        else:
            print("No analysis results available. Run an analysis first.")
        return
    
    try:
        if COMPATIBLE_OUTPUT:
            print_status("Generating comprehensive report...", "info")
        else:
            print("Generating comprehensive report...")
        
        # Collect all analysis results
        analysis_results = report_generator.collect_analysis_results()
        
        # Generate the report
        report_path = report_generator.generate_plaintext_report(analysis_results, output_mode)
        
        if COMPATIBLE_OUTPUT:
            print_status(f"Report generated successfully: {report_path}", "success")
            output.print("")
            output.print("[blue]Report contains comprehensive analysis of:[/blue]")
            output.print("- Email file information and security verdict")
            output.print("- Complete header analysis and routing details")
            output.print("- IP address reputation analysis")
            output.print("- URL analysis from email body and attachments")
            output.print("- Email body content and phishing pattern analysis")
            output.print("- Detailed attachment analysis including QR codes")
        else:
            print(f"Report generated successfully: {report_path}")
            print("")
            print("Report contains comprehensive analysis of:")
            print("- Email file information and security verdict")
            print("- Complete header analysis and routing details")
            print("- IP address reputation analysis")
            print("- URL analysis from email body and attachments")
            print("- Email body content and phishing pattern analysis")
            print("- Detailed attachment analysis including QR codes")
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error generating report: {e}", "error")
            print_status("Please ensure analysis has been completed successfully.", "warning")
        else:
            print(f"Error generating report: {e}")
            print("Please ensure analysis has been completed successfully.")

def main():
    """Main application entry point with comprehensive error handling."""
    global output_mode, last_url_analysis_results, last_received_hops, last_body_analysis_results, last_attachment_results
    
    try:
        parser_args = argparse.ArgumentParser(description="Phishing Email Analyzer")
        parser_args.add_argument("file_path", nargs="?", help="Path to .eml or .msg file")
        args = parser_args.parse_args()

        file_path_arg = args.file_path
        
        # Load saved settings at startup
        try:
            vt_api_key = get_saved_api_key()
            output_mode = get_saved_output_mode()
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Warning: Could not load saved settings: {e}", "warning")
            else:
                print(f"Warning: Could not load saved settings: {e}")
            vt_api_key = None
            output_mode = "fanged"

        # Main application loop
        while True:
            try:
                # Build menu options dynamically - FIXED with comprehensive None checking
                menu_options = []
                
                # Check URL findings - FIXED with better None checking
                has_url_findings = False
                if last_url_analysis_results and isinstance(last_url_analysis_results, list):
                    has_url_findings = True
                if last_attachment_results and isinstance(last_attachment_results, list):
                    valid_attachments = [a for a in last_attachment_results if a is not None and isinstance(a, dict)]
                    if any(a.get('attachment_content_analysis', {}).get('url_analysis', {}).get('results') for a in valid_attachments):
                        has_url_findings = True
                
                if has_url_findings:
                    menu_options.append(("4", "View URL findings"))
                
                # Check body analysis
                if last_body_analysis_results and isinstance(last_body_analysis_results, dict):
                    next_num = str(len(menu_options) + 4)
                    menu_options.append((next_num, "View body analysis details"))
                
                # Check received hops
                if last_received_hops and isinstance(last_received_hops, list):
                    next_num = str(len(menu_options) + 4)
                    menu_options.append((next_num, "View email routing hops"))
                
                # Add executive summary option if any analysis has been run
                has_any_results = False
                if last_url_analysis_results and isinstance(last_url_analysis_results, list):
                    has_any_results = True
                elif last_body_analysis_results and isinstance(last_body_analysis_results, dict):
                    has_any_results = True
                elif last_attachment_results and isinstance(last_attachment_results, list):
                    valid_attachments = [a for a in last_attachment_results if a is not None and isinstance(a, dict)]
                    if valid_attachments:
                        has_any_results = True
                elif last_ip_analysis_results and isinstance(last_ip_analysis_results, list):
                    has_any_results = True
                elif last_received_hops and isinstance(last_received_hops, list):
                    has_any_results = True
                
                if has_any_results:
                    next_num = str(len(menu_options) + 4)
                    menu_options.append((next_num, "Generate executive summary"))
                    
                    # Add comprehensive report option
                    next_num = str(len(menu_options) + 4)
                    menu_options.append((next_num, "Generate comprehensive report"))

                exit_num = str(len(menu_options) + 4)
                max_option = int(exit_num)

                if COMPATIBLE_OUTPUT:
                    output.print("\n[magenta]===== MAIN MENU =====[/magenta]")
                    output.print("[blue]1:[/blue] Start script [ENTER]")
                    output.print("[blue]2:[/blue] VirusTotal API Settings")
                    output.print("[blue]3:[/blue] Output Settings")
                    
                    for num, desc in menu_options:
                        output.print(f"[blue]{num}:[/blue] {desc}")
                    
                    output.print(f"[blue]{exit_num}:[/blue] Exit")
                else:
                    print("\n===== MAIN MENU =====")
                    print("1: Start script [ENTER]")
                    print("2: VirusTotal API Settings")
                    print("3: Output Settings")
                    
                    for num, desc in menu_options:
                        print(f"{num}: {desc}")
                    
                    print(f"{exit_num}: Exit")

                # Configuration display
                print_current_config(vt_api_key, output_mode)

                choice = safe_input(f"Enter option [1-{max_option}] (default 1): ", "1")
                if choice is None:  # User cancelled
                    break

                if choice == "" or choice == "1":
                    # Start script
                    if not file_path_arg:
                        file_path = safe_input("Enter path to .eml or .msg file: ")
                        if file_path is None:  # User cancelled
                            continue
                        if not file_path:
                            print("No file path provided. Returning to main menu.")
                            continue
                    else:
                        file_path = file_path_arg

                    # Refresh API key each run
                    try:
                        vt_api_key = get_saved_api_key()
                    except Exception:
                        pass
                    
                    run_analysis(file_path, vt_api_key)
                    
                elif choice == "2":
                    # VirusTotal API Settings submenu
                    try:
                        vt_api_key = prompt_api_key_menu()
                    except Exception as e:
                        if COMPATIBLE_OUTPUT:
                            print_status(f"Error in API settings: {e}", "error")
                        else:
                            print(f"Error in API settings: {e}")
                        continue
                        
                elif choice == "3":
                    # Output Settings submenu
                    try:
                        handle_output_settings()
                    except Exception as e:
                        if COMPATIBLE_OUTPUT:
                            print_status(f"Error in output settings: {e}", "error")
                        else:
                            print(f"Error in output settings: {e}")
                        continue
                        
                # Handle dynamic menu options
                else:
                    # Find which option was selected
                    selected_option = None
                    for num, desc in menu_options:
                        if choice == num:
                            selected_option = desc
                            break
                    
                    if selected_option == "View URL findings":
                        try:
                            view_url_findings()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error viewing URL findings: {e}", "error")
                            else:
                                print(f"Error viewing URL findings: {e}")
                    elif selected_option == "View body analysis details":
                        try:
                            view_body_analysis_details()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error viewing body analysis details: {e}", "error")
                            else:
                                print(f"Error viewing body analysis details: {e}")
                    elif selected_option == "View email routing hops":
                        try:
                            view_received_hops()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error viewing email routing hops: {e}", "error")
                            else:
                                print(f"Error viewing email routing hops: {e}")
                    elif selected_option == "Generate executive summary":
                        try:
                            generate_comprehensive_executive_summary()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error generating executive summary: {e}", "error")
                            else:
                                print(f"Error generating executive summary: {e}")
                    elif selected_option == "Generate comprehensive report":
                        try:
                            generate_comprehensive_report()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error generating comprehensive report: {e}", "error")
                            else:
                                print(f"Error generating comprehensive report: {e}")
                    elif choice == exit_num:
                        print("Exiting.")
                        break
                    else:
                        print("Invalid input. Please enter a valid option number.")
                    
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error in main menu: {e}", "error")
                else:
                    print(f"Error in main menu: {e}")
                continue
    
    except KeyboardInterrupt:
        print("\n\nExiting...")
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Unexpected error: {e}", "error")
            print_status("Please report this error if it persists.", "warning")
        else:
            print(f"\n\nUnexpected error: {e}")
            print("Please report this error if it persists.")
        sys.exit(1)

if __name__ == "__main__":
    main()