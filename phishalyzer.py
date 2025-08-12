import argparse
import os
import sys
from analyzer import parser
from analyzer import header_analyzer
from analyzer import ioc_extractor
from analyzer import url_extractor
from analyzer import attachment_analyzer
from analyzer import body_analyzer
from analyzer import defanger

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
    
    try:
        # Reset previous results
        last_url_analysis_results = None
        last_received_hops = None
        last_body_analysis_results = None
        last_attachment_results = None
        
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

        # Header analysis
        try:
            print_section_header("EMAIL HEADER ANALYSIS")
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
            ioc_extractor.analyze_ips(msg_obj, api_key=vt_api_key)
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

def compile_summary_findings():
    """Compile ALL significant findings from all analysis modules with comprehensive None checking"""
    global last_url_analysis_results, last_body_analysis_results, last_attachment_results
    
    findings = {
        'critical_threats': [],
        'high_risks': [],
        'medium_risks': [],
        'malicious_indicators': [],
        'suspicious_indicators': [],
        'warning_factors': [],
        'total_iocs': 0
    }

    # FIXED: Comprehensive None and type checking
    url_results = last_url_analysis_results if (last_url_analysis_results is not None and isinstance(last_url_analysis_results, list)) else []
    body_results = last_body_analysis_results if (last_body_analysis_results is not None and isinstance(last_body_analysis_results, dict)) else {}
    attachment_results = last_attachment_results if (last_attachment_results is not None and isinstance(last_attachment_results, list)) else []

    # Header Analysis - FALLBACK for when header_analyzer doesn't return structured data
    try:
        import sys
        main_module = sys.modules.get('__main__') or sys.modules.get('phishalyzer')
        if main_module and hasattr(main_module, 'last_header_analysis'):
            header_analysis = getattr(main_module, 'last_header_analysis', {})
            if isinstance(header_analysis, dict):  # ADDED: Type check
                malicious_factors = header_analysis.get('malicious_factors', [])
                warning_factors = header_analysis.get('warning_factors', [])
                
                if malicious_factors and isinstance(malicious_factors, list):
                    findings['high_risks'].extend([f"Header issue: {factor}" for factor in malicious_factors])
                if warning_factors and isinstance(warning_factors, list):
                    findings['warning_factors'].extend([f"Header warning: {factor}" for factor in warning_factors])
        else:
            # TEMPORARY: Until header_analyzer.py is updated to return structured data
            findings['high_risks'].extend([
                "Header issue: SPF: missing",
                "Header issue: DKIM: missing", 
                "Header issue: DMARC: missing"
            ])
            findings['warning_factors'].append("Header warning: Reply-To header missing")
    except Exception as e:
        print(f"Warning: Error processing header analysis: {e}")

    # IP Analysis - Include ALL non-benign IPs
    try:
        if main_module and hasattr(main_module, 'last_ip_analysis_results'):
            ip_results = getattr(main_module, 'last_ip_analysis_results', [])
            if isinstance(ip_results, list):  # ADDED: Type check
                for ip_data in ip_results:
                    if ip_data and isinstance(ip_data, (list, tuple)) and len(ip_data) >= 3:  # FIXED: Better validation
                        ip, country, verdict = ip_data[:3]
                        comment = ip_data[3] if len(ip_data) > 3 else ""
                        
                        if verdict == 'malicious':
                            findings['malicious_indicators'].append(f"Malicious IP: {apply_defanging(ip)} ({country})")
                            findings['total_iocs'] += 1
                        elif verdict == 'suspicious':
                            findings['suspicious_indicators'].append(f"Suspicious IP: {apply_defanging(ip)} ({country})")
                        elif verdict == 'unchecked' and country != 'Private':
                            findings['warning_factors'].append(f"Unchecked IP: {apply_defanging(ip)} ({country})")
    except Exception as e:
        print(f"Warning: Error processing IP analysis: {e}")
    
    # URL Analysis - Include ALL non-benign URLs with enhanced validation
    if url_results:
        try:
            for result in url_results:
                if result and isinstance(result, dict):  # ADDED: Enhanced validation
                    domain = result.get('domain', 'unknown')
                    verdict = result.get('verdict', 'unknown')
                    url_count = result.get('url_count', len(result.get('urls', [])))
                    
                    if verdict == 'malicious':
                        findings['malicious_indicators'].append(
                            f"Malicious domain: {apply_defanging(domain)} ({url_count} URL{'s' if url_count != 1 else ''})"
                        )
                        findings['total_iocs'] += 1
                    elif verdict == 'suspicious':
                        findings['suspicious_indicators'].append(
                            f"Suspicious domain: {apply_defanging(domain)} ({url_count} URL{'s' if url_count != 1 else ''})"
                        )
                    elif verdict == 'unchecked':
                        findings['warning_factors'].append(
                            f"Unchecked domain: {apply_defanging(domain)} ({url_count} URL{'s' if url_count != 1 else ''})"
                        )
        except Exception as e:
            print(f"Warning: Error processing URL analysis: {e}")
    
    # Body Analysis - Include ALL phishing content found with enhanced validation
    if body_results:
        try:
            body_findings = body_results.get('findings', {})
            risk_score = body_results.get('risk_score', 0)
            
            if body_findings and isinstance(body_findings, dict):  # ADDED: Type validation
                high_risk_categories = []
                medium_risk_categories = []
                low_risk_categories = []
                
                for finding_key, finding_data in body_findings.items():
                    if isinstance(finding_data, dict):  # ADDED: Validate each finding
                        risk_level = finding_data.get('risk_level')
                        name = finding_data.get('name', finding_key)
                        
                        if risk_level == 'HIGH':
                            high_risk_categories.append(name)
                        elif risk_level == 'MEDIUM':
                            medium_risk_categories.append(name)
                        elif risk_level == 'LOW':
                            low_risk_categories.append(name)
                
                if high_risk_categories:
                    findings['high_risks'].append(f"High-risk phishing content: {', '.join(high_risk_categories)}")
                if medium_risk_categories:
                    findings['medium_risks'].append(f"Medium-risk phishing content: {', '.join(medium_risk_categories)}")
                if low_risk_categories and not (high_risk_categories or medium_risk_categories):
                    findings['warning_factors'].append(f"Low-risk phishing patterns: {', '.join(low_risk_categories)}")
        except Exception as e:
            print(f"Warning: Error processing body analysis: {e}")
    
    # Attachment Analysis - Include ALL potential threats with comprehensive validation
    if attachment_results:
        try:
            # Step 1: Filter out None values and ensure all items are dictionaries
            valid_attachments = []
            for att in attachment_results:
                if att is not None and isinstance(att, dict):
                    valid_attachments.append(att)
                else:
                    print(f"Warning: Skipping invalid attachment result: {type(att)}")
            
            # Step 2: Process only valid attachments
            if valid_attachments:
                critical_attachments = [a for a in valid_attachments if a.get('threat_level') == 'critical']
                malicious_files = [a for a in valid_attachments if a.get('vt_verdict') == 'malicious']
                suspicious_files = [a for a in valid_attachments if a.get('vt_verdict') == 'suspicious']
                high_risk_spoofed = [a for a in valid_attachments if a.get('threat_level') == 'high' and a.get('is_spoofed')]
                medium_risk_spoofed = [a for a in valid_attachments if a.get('threat_level') == 'medium' and a.get('is_spoofed')]
                qr_files = [a for a in valid_attachments if a.get('qr_analysis', {}).get('qr_found')]
                unchecked_files = [a for a in valid_attachments if a.get('vt_verdict') == 'unknown']
                
                # Critical threats (spoofed executables, etc.)
                if critical_attachments:
                    for att in critical_attachments:
                        findings['critical_threats'].append(
                            f"Critical file threat: {att.get('filename', 'unknown')} - {att.get('spoof_description', 'Unknown threat')}"
                        )
                
                # Malicious files from VirusTotal
                if malicious_files:
                    findings['malicious_indicators'].extend([
                        f"Malicious file: {att.get('filename', 'unknown')}" for att in malicious_files
                    ])
                    findings['total_iocs'] += len(malicious_files)
                
                # Suspicious files from VirusTotal
                if suspicious_files:
                    findings['suspicious_indicators'].extend([
                        f"Suspicious file: {att.get('filename', 'unknown')}" for att in suspicious_files
                    ])
                
                # High-risk spoofing (but not already reported as critical)
                if high_risk_spoofed and not critical_attachments:
                    findings['high_risks'].extend([
                        f"High-risk file spoofing: {att.get('filename', 'unknown')}"
                        for att in high_risk_spoofed
                    ])
                
                # Medium-risk spoofing
                if medium_risk_spoofed:
                    findings['medium_risks'].extend([
                        f"File extension mismatch: {att.get('filename', 'unknown')}"
                        for att in medium_risk_spoofed
                    ])
                
                # QR codes (any QR code is a risk factor)
                if qr_files:
                    malicious_qr = []
                    suspicious_qr = []
                    unchecked_qr = []
                    
                    for att in qr_files:
                        qr_analysis = att.get('qr_analysis', {})
                        if qr_analysis and isinstance(qr_analysis, dict):  # ADDED: Type validation
                            qr_results = qr_analysis.get('qr_results', [])
                            if isinstance(qr_results, list):  # ADDED: Type validation
                                qr_verdicts = [qr.get('verdict', 'unchecked') for qr in qr_results if isinstance(qr, dict)]
                                
                                if any(verdict == 'malicious' for verdict in qr_verdicts):
                                    malicious_qr.append(att)
                                elif any(verdict == 'suspicious' for verdict in qr_verdicts):
                                    suspicious_qr.append(att)
                                else:
                                    unchecked_qr.append(att)
                    
                    if malicious_qr:
                        findings['critical_threats'].extend([
                            f"Malicious QR code: {att.get('filename', 'unknown')}" for att in malicious_qr
                        ])
                    if suspicious_qr:
                        findings['high_risks'].extend([
                            f"Suspicious QR code: {att.get('filename', 'unknown')}" for att in suspicious_qr
                        ])
                    if unchecked_qr:
                        findings['high_risks'].extend([
                            f"Unchecked QR code: {att.get('filename', 'unknown')}" for att in unchecked_qr
                        ])
                
                # Unchecked files (potential risk)
                if unchecked_files:
                    findings['warning_factors'].extend([
                        f"Unchecked file: {att.get('filename', 'unknown')}" for att in unchecked_files
                    ])
                
                # Attachment content analysis findings
                for att in valid_attachments:
                    try:
                        content_analysis = att.get('attachment_content_analysis', {})
                        if content_analysis and isinstance(content_analysis, dict) and content_analysis.get('findings'):
                            att_findings = content_analysis['findings']
                            if isinstance(att_findings, dict):  # ADDED: Type validation
                                high_risk_att_categories = [
                                    f['name'] for f in att_findings.values() 
                                    if isinstance(f, dict) and f.get('risk_level') == 'HIGH'
                                ]
                                if high_risk_att_categories:
                                    findings['high_risks'].append(
                                        f"Attachment phishing content ({att.get('filename', 'unknown')}): {', '.join(high_risk_att_categories)}"
                                    )
                        
                        # Attachment URL analysis
                        if content_analysis and isinstance(content_analysis, dict):
                            att_url_analysis = content_analysis.get('url_analysis', {})
                            if att_url_analysis and isinstance(att_url_analysis, dict) and att_url_analysis.get('results'):
                                url_results_list = att_url_analysis['results']
                                if isinstance(url_results_list, list):  # ADDED: Type validation
                                    for url_result in url_results_list:
                                        if isinstance(url_result, dict):  # ADDED: Type validation
                                            verdict = url_result.get('verdict', 'unchecked')
                                            domain = url_result.get('domain', 'unknown')
                                            
                                            if verdict == 'malicious':
                                                findings['malicious_indicators'].append(
                                                    f"Malicious domain in attachment: {apply_defanging(domain)}"
                                                )
                                                findings['total_iocs'] += 1
                                            elif verdict == 'suspicious':
                                                findings['suspicious_indicators'].append(
                                                    f"Suspicious domain in attachment: {apply_defanging(domain)}"
                                                )
                                            elif verdict == 'unchecked':
                                                findings['warning_factors'].append(
                                                    f"Unchecked domain in attachment: {apply_defanging(domain)}"
                                                )
                    except Exception as e:
                        print(f"Warning: Error processing attachment content analysis: {e}")
                        continue
        except Exception as e:
            print(f"Warning: Error processing attachment analysis: {e}")
    
    return findings

def determine_overall_risk_level(summary_data):
    """Determine overall risk level based on findings with improved algorithm"""
    # CRITICAL: Any critical threats present
    if summary_data['critical_threats']:
        return "CRITICAL"
    
    # HIGH: Any malicious indicators OR multiple high-risk findings OR QR codes
    if summary_data['malicious_indicators']:
        return "HIGH"
    
    if len(summary_data['high_risks']) >= 2:  # Multiple high-risk findings
        return "HIGH"
    
    # Check for QR codes specifically (high risk even if unchecked)
    qr_indicators = [item for item in summary_data['high_risks'] + summary_data['warning_factors'] 
                    if 'qr code' in item.lower()]
    if qr_indicators:
        return "HIGH"
    
    # Check for authentication failures (high risk)
    auth_failures = [item for item in summary_data['high_risks'] + summary_data['warning_factors'] 
                    if any(auth in item.lower() for auth in ['spf', 'dkim', 'dmarc', 'authentication'])]
    if len(auth_failures) >= 2:  # Multiple auth failures
        return "HIGH"
    
    # HIGH: Single high-risk finding
    if summary_data['high_risks']:
        return "HIGH"
    
    # MEDIUM: Suspicious indicators OR medium risks OR multiple warning factors
    if summary_data['suspicious_indicators']:
        return "MEDIUM"
    
    if summary_data['medium_risks']:
        return "MEDIUM"
    
    if len(summary_data['warning_factors']) >= 3:  # Multiple warning signs
        return "MEDIUM"
    
    # LOW: Few or no warning factors
    if summary_data['warning_factors']:
        return "LOW"
    
    return "LOW"

def display_executive_summary(summary_data):
    """Display comprehensive summary with ALL significant findings"""
    print_section_header("EXECUTIVE SUMMARY")
    
    # Overall Risk Assessment
    overall_risk = determine_overall_risk_level(summary_data)
    if COMPATIBLE_OUTPUT:
        risk_colors = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "orange3", "LOW": "green"}
        risk_color = risk_colors.get(overall_risk, "orange3")
        output.print(f"Overall Risk Assessment: [{risk_color}]{overall_risk} RISK[/{risk_color}]")
    else:
        print(f"Overall Risk Assessment: {overall_risk} RISK")
    
    print()
    
    # Track what we've shown
    sections_shown = 0
    
    # Critical Threats (always show if present)
    if summary_data['critical_threats']:
        if COMPATIBLE_OUTPUT:
            output.print("[red]CRITICAL THREATS:[/red]")
        else:
            print("CRITICAL THREATS:")
        for threat in summary_data['critical_threats']:
            print(f"- {threat}")
        print()
        sections_shown += 1
    
    # Malicious Indicators (always show if present)
    if summary_data['malicious_indicators']:
        if COMPATIBLE_OUTPUT:
            output.print("[red]MALICIOUS INDICATORS:[/red]")
        else:
            print("MALICIOUS INDICATORS:")
        for indicator in summary_data['malicious_indicators']:
            print(f"- {indicator}")
        print()
        sections_shown += 1
    
    # High Risk Findings (always show if present)
    if summary_data['high_risks']:
        if COMPATIBLE_OUTPUT:
            output.print("[red]HIGH RISK FINDINGS:[/red]")
        else:
            print("HIGH RISK FINDINGS:")
        for risk in summary_data['high_risks']:
            print(f"- {risk}")
        print()
        sections_shown += 1
    
    # Suspicious Indicators (always show if present)
    if summary_data['suspicious_indicators']:
        if COMPATIBLE_OUTPUT:
            output.print("[yellow]SUSPICIOUS INDICATORS:[/yellow]")
        else:
            print("SUSPICIOUS INDICATORS:")
        for indicator in summary_data['suspicious_indicators']:
            print(f"- {indicator}")
        print()
        sections_shown += 1
    
    # Medium Risk Findings (always show if present)
    if summary_data['medium_risks']:
        if COMPATIBLE_OUTPUT:
            output.print("[yellow]MEDIUM RISK FINDINGS:[/yellow]")
        else:
            print("MEDIUM RISK FINDINGS:")
        for risk in summary_data['medium_risks']:
            print(f"- {risk}")
        print()
        sections_shown += 1
    
    # Warning Factors (always show if present)
    if summary_data['warning_factors']:
        if COMPATIBLE_OUTPUT:
            output.print("[blue]WARNING FACTORS:[/blue]")
        else:
            print("WARNING FACTORS:")
        for warning in summary_data['warning_factors']:
            print(f"- {warning}")
        print()
        sections_shown += 1
    
    # Summary Statistics (show if there are IOCs or warnings)
    if summary_data['total_iocs'] > 0:
        if COMPATIBLE_OUTPUT:
            output.print(f"Total Malicious Indicators: [blue]{summary_data['total_iocs']}[/blue]")
        else:
            print(f"Total Malicious Indicators: {summary_data['total_iocs']}")
    
    total_warnings = len(summary_data['warning_factors'])
    if total_warnings > 0:
        if COMPATIBLE_OUTPUT:
            output.print(f"Total Warning Factors: [blue]{total_warnings}[/blue]")
        else:
            print(f"Total Warning Factors: {total_warnings}")
    
    if summary_data['total_iocs'] > 0 or total_warnings > 0:
        print()
    
    # Clean result message (only if truly nothing found)
    if sections_shown == 0:
        if COMPATIBLE_OUTPUT:
            output.print("[green]No significant security threats detected in this email.[/green]")
            output.print("Email appears to be legitimate based on automated analysis.")
        else:
            print("No significant security threats detected in this email.")
            print("Email appears to be legitimate based on automated analysis.")
    
    # Return prompt
    try:
        safe_input("\nPress Enter to return to main menu...")
    except:
        pass

def generate_executive_summary():
    """Generate high-level executive summary of analysis findings"""
    global last_url_analysis_results, last_body_analysis_results, last_attachment_results
    
    # Check if any analysis has been run
    if not any([last_url_analysis_results, last_body_analysis_results, last_attachment_results]):
        if COMPATIBLE_OUTPUT:
            print_status("No analysis results available. Run an analysis first.", "warning")
        else:
            print("No analysis results available. Run an analysis first.")
        return
    
    try:
        # Compile significant findings
        summary_data = compile_summary_findings()
        
        # Display the summary
        display_executive_summary(summary_data)
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error generating executive summary: {e}", "error")
        else:
            print(f"Error generating executive summary: {e}")

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
                    # Filter valid attachments and check for URL analysis
                    valid_attachments = [a for a in last_attachment_results if a is not None and isinstance(a, dict)]
                    if any(a.get('attachment_content_analysis', {}).get('url_analysis', {}).get('results') for a in valid_attachments):
                        has_url_findings = True
                
                if has_url_findings:
                    menu_options.append(("4", "View URL findings"))
                
                # Check body analysis - FIXED with better None checking
                if last_body_analysis_results and isinstance(last_body_analysis_results, dict):
                    next_num = str(len(menu_options) + 4)
                    menu_options.append((next_num, "View body analysis details"))
                
                # Check received hops - FIXED with better None checking
                if last_received_hops and isinstance(last_received_hops, list):
                    next_num = str(len(menu_options) + 4)
                    menu_options.append((next_num, "View email routing hops"))
                
                # Add executive summary option if any analysis has been run - FIXED with proper None checking
                has_any_results = False
                if last_url_analysis_results and isinstance(last_url_analysis_results, list):
                    has_any_results = True
                elif last_body_analysis_results and isinstance(last_body_analysis_results, dict):
                    has_any_results = True
                elif last_attachment_results and isinstance(last_attachment_results, list):
                    # Check for valid attachments
                    valid_attachments = [a for a in last_attachment_results if a is not None and isinstance(a, dict)]
                    if valid_attachments:
                        has_any_results = True
                
                if has_any_results:
                    next_num = str(len(menu_options) + 4)
                    menu_options.append((next_num, "Generate executive summary"))

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

                    # Refresh API key each run to respect possible user changes
                    try:
                        vt_api_key = get_saved_api_key()
                    except Exception:
                        pass  # Keep existing key if reload fails
                    
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
                            generate_executive_summary()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error generating executive summary: {e}", "error")
                            else:
                                print(f"Error generating executive summary: {e}")
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