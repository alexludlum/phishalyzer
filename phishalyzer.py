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

# Replace these TWO functions in phishalyzer.py

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
    global last_url_analysis_results, last_received_hops, last_body_analysis_results
    
    try:
        # Reset previous results
        last_url_analysis_results = None
        last_received_hops = None
        last_body_analysis_results = None
        
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
            attachment_analyzer.analyze_attachments(msg_obj, api_key=vt_api_key)
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error during attachment analysis: {e}", "error")
                print_status("Skipping attachment analysis and continuing...", "warning")
            else:
                print(f"Error during attachment analysis: {e}")
                print("Skipping attachment analysis and continuing...")
        
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

def view_collapsed_urls():
    """Display detailed URLs with COMPLETELY FIXED defanging and universal output."""
    global last_url_analysis_results
    
    if not last_url_analysis_results:
        if COMPATIBLE_OUTPUT:
            print_status("No URL analysis results available. Run an analysis first.", "warning")
        else:
            print("No URL analysis results available. Run an analysis first.")
        return
    
    try:
        # Use the universal output system throughout - ZERO regular print() calls!
        print_section_header("COMPLETE URL BREAKDOWN")
        
        for i, result in enumerate(last_url_analysis_results):
            # Add spacing between domains (but not before the first one)
            if i > 0:
                if COMPATIBLE_OUTPUT:
                    output.print("")  # Use output.print for blank lines
                else:
                    print()
            
            domain = result['domain']
            urls = result['urls']
            verdict = result['verdict']
            
            # Apply defanging to domain using centralized function
            display_domain = apply_defanging(domain)
            
            # FIXED: Build and display the header with proper color handling
            if COMPATIBLE_OUTPUT:
                escaped_domain = output.escape(display_domain)
                
                # Color code the verdict text based on verdict type
                if verdict == "malicious":
                    verdict_colored = output.colorize("MALICIOUS", "red")
                elif verdict == "suspicious":
                    verdict_colored = output.colorize("SUSPICIOUS", "orange3")
                elif verdict == "benign":
                    verdict_colored = output.colorize("BENIGN", "green")
                else:
                    verdict_colored = output.colorize("UNCHECKED", "orange3")
                
                # Build header with escaped domain and pre-colored verdict
                header_text = f"{escaped_domain} - {verdict_colored} ({len(urls)} URL{'s' if len(urls) != 1 else ''}):"
                print(header_text)  # Use regular print since verdict is already colored
            else:
                # For non-compatible terminals
                clean_verdict = verdict.upper()
                print(f"{display_domain} - {clean_verdict} ({len(urls)} URL{'s' if len(urls) != 1 else ''}):")
            
            # Display each URL with defanging
            for j, url in enumerate(urls, 1):
                # Apply defanging to each individual URL
                display_url = apply_defanging(url)
                escaped_url = output.escape(display_url) if COMPATIBLE_OUTPUT else display_url
                
                url_line = f"  {j:2}. {escaped_url}"
                if COMPATIBLE_OUTPUT:
                    output.print(url_line)
                else:
                    print(f"  {j:2}. {display_url}")
        
        # Summary
        total_urls = sum(len(r['urls']) for r in last_url_analysis_results)
        total_domains = len(last_url_analysis_results)
        summary_text = f"Total: {total_urls} URL{'s' if total_urls != 1 else ''} across {total_domains} domain{'s' if total_domains != 1 else ''}"
        
        if COMPATIBLE_OUTPUT:
            output.print(f"\n{summary_text}")
        else:
            print(f"\n{summary_text}")
        
        # Return prompt
        try:
            safe_input("\nPress Enter to return to main menu...")
        except:
            pass  # User pressed Ctrl+C or similar, just return
                
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error displaying URL details: {e}", "error")
        else:
            print(f"Error displaying URL details: {e}")

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

def main():
    """Main application entry point with comprehensive error handling."""
    global output_mode, last_url_analysis_results, last_received_hops, last_body_analysis_results
    
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
                # Build menu options dynamically
                menu_options = []
                if last_url_analysis_results:
                    menu_options.append(("4", "View collapsed URL variations"))
                if last_body_analysis_results:
                    next_num = str(len(menu_options) + 4)
                    menu_options.append((next_num, "View body analysis details"))
                if last_received_hops:
                    next_num = str(len(menu_options) + 4)
                    menu_options.append((next_num, "View email routing hops"))

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
                        
                elif choice == "4":
                    if last_url_analysis_results:
                        # View URL details
                        try:
                            view_collapsed_urls()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error viewing URL details: {e}", "error")
                            else:
                                print(f"Error viewing URL details: {e}")
                            continue
                    elif last_body_analysis_results:
                        # View body analysis details
                        try:
                            view_body_analysis_details()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error viewing body analysis details: {e}", "error")
                            else:
                                print(f"Error viewing body analysis details: {e}")
                            continue
                    elif last_received_hops:
                        # View hops
                        try:
                            view_received_hops()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error viewing hops: {e}", "error")
                            else:
                                print(f"Error viewing hops: {e}")
                            continue
                    else:
                        # Exit
                        print("Exiting.")
                        break

                elif choice == "5":
                    # This could be body analysis, hops, or exit depending on what's available
                    if last_url_analysis_results and last_body_analysis_results:
                        # View body analysis details
                        try:
                            view_body_analysis_details()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error viewing body analysis details: {e}", "error")
                            else:
                                print(f"Error viewing body analysis details: {e}")
                            continue
                    elif last_url_analysis_results and last_received_hops:
                        # View hops (no body analysis available)
                        try:
                            view_received_hops()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error viewing hops: {e}", "error")
                            else:
                                print(f"Error viewing hops: {e}")
                            continue
                    elif last_body_analysis_results and last_received_hops:
                        # View hops (no URL analysis available)
                        try:
                            view_received_hops()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error viewing hops: {e}", "error")
                            else:
                                print(f"Error viewing hops: {e}")
                            continue
                    else:
                        # Exit
                        print("Exiting.")
                        break

                elif choice == "6":
                    # This could be hops or exit
                    if last_url_analysis_results and last_body_analysis_results and last_received_hops:
                        # View hops (all three available)
                        try:
                            view_received_hops()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Error viewing hops: {e}", "error")
                            else:
                                print(f"Error viewing hops: {e}")
                            continue
                    else:
                        # Exit
                        print("Exiting.")
                        break

                elif choice == exit_num:
                    # Exit
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