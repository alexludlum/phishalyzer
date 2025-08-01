import argparse
import os
import sys
from analyzer import parser
from analyzer import header_analyzer
from analyzer import ioc_extractor
from analyzer import url_extractor
from analyzer import attachment_analyzer
from analyzer import defanger
from rich import print
from rich.text import Text

API_KEY_FILE = os.path.expanduser("~/.phishalyzer_vt_api_key")
OUTPUT_MODE_FILE = os.path.expanduser("~/.phishalyzer_output_mode")

output_mode = "fanged"  # default output mode - accessible globally

def print_section_header(title: str):
    """Print a standardized section header with consistent formatting."""
    try:
        # Calculate padding to make all headers the same width (50 characters total)
        total_width = 50
        title_with_spaces = f" {title.upper()} "
        padding_needed = total_width - len(title_with_spaces)
        left_padding = padding_needed // 2
        right_padding = padding_needed - left_padding
        
        header_line = "=" * left_padding + title_with_spaces + "=" * right_padding
        print(f"\n{header_line}\n")
    except Exception as e:
        # Fallback to simple header if formatting fails
        print(f"\n=== {title.upper()} ===\n")

def safe_file_read(filepath, default_value=""):
    """Safely read a file with error handling."""
    try:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding='utf-8') as f:
                content = f.read().strip()
                return content if content else default_value
    except (PermissionError, IOError, OSError, UnicodeDecodeError) as e:
        print(f"[yellow]Warning: Could not read {os.path.basename(filepath)}: {e}[/yellow]")
    except Exception as e:
        print(f"[yellow]Unexpected error reading {os.path.basename(filepath)}: {e}[/yellow]")
    return default_value

def safe_file_write(filepath, content):
    """Safely write to a file with error handling."""
    try:
        with open(filepath, "w", encoding='utf-8') as f:
            f.write(content.strip())
        return True
    except (PermissionError, IOError, OSError) as e:
        print(f"[red]Error: Could not save to {os.path.basename(filepath)}: {e}[/red]")
        print("[yellow]Settings will not persist between sessions.[/yellow]")
        return False
    except Exception as e:
        print(f"[red]Unexpected error saving {os.path.basename(filepath)}: {e}[/red]")
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
        print(f"[red]Error: Could not delete {os.path.basename(filepath)}: {e}[/red]")
        return False
    except Exception as e:
        print(f"[red]Unexpected error deleting {os.path.basename(filepath)}: {e}[/red]")
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
            print(f"[red]Error: Invalid output mode '{mode}'[/red]")
            return False
        return safe_file_write(OUTPUT_MODE_FILE, mode)
    except Exception as e:
        print(f"[red]Error saving output mode: {e}[/red]")
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
            print("[red]Error: API key appears invalid (too short)[/red]")
            return False
        return safe_file_write(API_KEY_FILE, key)
    except Exception as e:
        print(f"[red]Error saving API key: {e}[/red]")
        return False

def safe_input(prompt, default=""):
    """Safely get user input with interruption handling."""
    try:
        response = input(prompt).strip()
        return response if response else default
    except (KeyboardInterrupt, EOFError):
        print(Text("\n\nOperation cancelled.", style=None))
        return None
    except Exception as e:
        print(f"[red]Input error: {e}[/red]")
        return default

def prompt_api_key_menu():
    """Handle VirusTotal API key management menu with error handling."""
    try:
        saved_key = get_saved_api_key()
        if saved_key:
            while True:
                try:
                    print("\nVirusTotal API Settings:")
                    print("1: View current API key")
                    print("2: Delete API key")
                    print("3: Enter a new API key")
                    print("4: Return to main menu")
                    
                    choice = safe_input("Enter option [1-4]: ")
                    if choice is None:  # User cancelled
                        return saved_key
                        
                    if choice == "1":
                        print(f"[blue]Saved API Key:[/blue] {saved_key}\n")
                    elif choice == "2":
                        if safe_file_delete(API_KEY_FILE):
                            print(Text("Saved API key deleted.\n", style="red"))
                            saved_key = None
                        else:
                            print(Text("Could not delete API key file.\n", style="orange3"))
                    elif choice == "3":
                        print(
                            "Enter your [blue]VirusTotal[/blue] API key "
                            "(create an account at https://virustotal.com/gui/my-apikey), or press Enter to cancel:"
                        )
                        user_key = safe_input("")
                        if user_key is None:  # User cancelled
                            print(Text("No changes made to API key.\n", style="yellow"))
                        elif user_key:
                            if save_api_key(user_key):
                                print(Text("API key saved for future runs.\n", style="green"))
                                saved_key = user_key
                            else:
                                print(Text("Failed to save API key.\n", style="red"))
                        else:
                            print(Text("No changes made to API key.\n", style="yellow"))
                    elif choice == "4":
                        return saved_key
                    else:
                        print("Invalid input. Please enter a number between 1 and 4.")
                except Exception as e:
                    print(f"[red]Error in API menu: {e}[/red]")
                    continue
        else:
            print(
                "No VirusTotal API key saved."
                "\nEnter your [blue]VirusTotal[/blue] API key "
                "(create an account at https://virustotal.com/gui/my-apikey), or press Enter to skip:"
            )
            user_key = safe_input("")
            if user_key is None:  # User cancelled
                print(Text("Continuing without VirusTotal API key. Reputation checks will be skipped.\n", style="yellow"))
                return None
            elif user_key:
                if save_api_key(user_key):
                    print(Text("API key saved for future runs.\n", style="green"))
                    return user_key
                else:
                    print(Text("Failed to save API key. Continuing without it.\n", style="red"))
                    return None
            else:
                print(Text("Continuing without VirusTotal API key. Reputation checks will be skipped.\n", style="yellow"))
                return None
    except Exception as e:
        print(f"[red]Error in API key management: {e}[/red]")
        print("[yellow]Continuing without API key changes.[/yellow]")
    
    return saved_key if 'saved_key' in locals() else None

def print_current_config(vt_api_key, output_mode):
    """Display current configuration status with error handling."""
    try:
        config_text = Text("Current configuration: Running ")
        
        if vt_api_key:
            config_text.append("with API key", style="blue")
        else:
            config_text.append("without API key", style="red")
        
        config_text.append(" and ")
        
        if output_mode == "fanged":
            config_text.append("fanged", style="red")
        else:
            config_text.append("defanged", style="green")
        
        config_text.append(" output format.\n")
        print(config_text)
    except Exception as e:
        print(f"Configuration: API key {'set' if vt_api_key else 'not set'}, {output_mode} mode\n")

def run_analysis(file_path, vt_api_key):
    """Run complete email analysis with comprehensive error handling."""
    try:
        # Validate file path
        if not file_path or not file_path.strip():
            print(Text("Error: No file path provided.", style="red"))
            return
        
        file_path = file_path.strip()
        
        # Check if file exists
        if not os.path.exists(file_path):
            print(Text(f"Error: File '{file_path}' not found.", style="red"))
            return
        
        # Check file size (warn about large files)
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # 100MB
                print(f"[yellow]Warning: Large file detected ({file_size // (1024*1024)}MB). Processing may be slow.[/yellow]")
        except OSError:
            pass  # Continue if we can't get file size
        
        # Show defanging status if enabled
        try:
            if output_mode == "defanged":
                status_text = Text()
                status_text.append("DEFANGED OUTPUT MODE: ", style="blue bold")
                status_text.append("URLs and IPs are displayed in safe format", style="green")
                print(status_text)
                print()
        except Exception:
            pass  # Non-critical display issue
        
        # Parse email file
        try:
            msg_obj, filetype = parser.load_email(file_path)
            print(f"Detected file type: {filetype}")
        except Exception as e:
            print(Text(f"Error: Could not parse email file: {e}", style="red"))
            print("[yellow]The file may be corrupted or in an unsupported format.[/yellow]")
            return
        
        # Display subject
        try:
            subject_text = Text("Subject: ")
            subject = msg_obj.get('Subject', 'No Subject') if msg_obj else 'No Subject'
            subject_text.append(str(subject))
            print(subject_text)
            print()
        except Exception as e:
            print(f"Subject: [Unable to read - {e}]")
            print()

        # Header analysis
        try:
            print_section_header("EMAIL HEADER ANALYSIS")
            header_analyzer.analyze_headers(msg_obj)
            print()
        except Exception as e:
            print(f"[red]Error during header analysis: {e}[/red]")
            print("[yellow]Skipping header analysis and continuing...[/yellow]")
            print()

        # IP analysis
        try:
            print_section_header("IP ADDRESS ANALYSIS")
            ioc_extractor.analyze_ips(msg_obj, api_key=vt_api_key)
            print()
        except Exception as e:
            print(f"[red]Error during IP analysis: {e}[/red]")
            print("[yellow]Skipping IP analysis and continuing...[/yellow]")
            print()

        # URL analysis
        try:
            print_section_header("URL ANALYSIS")
            url_extractor.analyze_urls(msg_obj, api_key=vt_api_key)
            print()
        except Exception as e:
            print(f"[red]Error during URL analysis: {e}[/red]")
            print("[yellow]Skipping URL analysis and continuing...[/yellow]")
            print()

        # Attachment analysis
        try:
            print_section_header("ATTACHMENT ANALYSIS")
            attachment_analyzer.analyze_attachments(msg_obj, api_key=vt_api_key)
        except Exception as e:
            print(f"[red]Error during attachment analysis: {e}[/red]")
            print("[yellow]Skipping attachment analysis and continuing...[/yellow]")
        
        print("[green]Analysis completed.[/green]")
        
    except KeyboardInterrupt:
        print(Text("\n\nAnalysis interrupted by user.", style="yellow"))
    except Exception as e:
        print(Text(f"Unexpected error during analysis: {str(e)}", style="red"))
        print("[yellow]Analysis could not be completed.[/yellow]")

def handle_output_settings():
    """Handle output settings submenu with error handling."""
    global output_mode
    
    try:
        while True:
            try:
                print("\nOutput Settings:")

                fanged_option = "1: Fanged"
                defanged_option = "2: Defanged"
                if output_mode == "fanged":
                    fanged_option += " ([red]current[/red])"
                elif output_mode == "defanged":
                    defanged_option += " ([green]current[/green])"

                print(fanged_option)
                print(defanged_option)
                print("3: Return to main menu")

                submenu_choice = safe_input("Enter option [1-3]: ")
                if submenu_choice is None:  # User cancelled
                    break

                if submenu_choice == "1":
                    output_mode = "fanged"
                    if save_output_mode(output_mode):
                        print("Output mode set to [red]Fanged[/red] and saved.")
                    else:
                        print("Output mode set to [red]Fanged[/red] but could not save setting.")
                    break
                elif submenu_choice == "2":
                    output_mode = "defanged"
                    if save_output_mode(output_mode):
                        print("Output mode set to [green]Defanged[/green] and saved.")
                    else:
                        print("Output mode set to [green]Defanged[/green] but could not save setting.")
                    break
                elif submenu_choice == "3":
                    break
                else:
                    print("Invalid input. Please enter 1, 2, or 3.")
            except Exception as e:
                print(f"[red]Error in output settings: {e}[/red]")
                continue
    except Exception as e:
        print(f"[red]Error in output settings menu: {e}[/red]")

def main():
    """Main application entry point with comprehensive error handling."""
    global output_mode
    
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
            print(f"[yellow]Warning: Could not load saved settings: {e}[/yellow]")
            vt_api_key = None
            output_mode = "fanged"

        # Main application loop
        while True:
            try:
                print("\nMain Menu:")
                print("1: Start script [ENTER]")
                print("2: VirusTotal API Settings")
                print("3: Output Settings")
                print("4: Exit")

                print_current_config(vt_api_key, output_mode)

                choice = safe_input("Enter option [1-4] (default 1): ", "1")
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
                        print(f"[red]Error in API settings: {e}[/red]")
                        continue
                        
                elif choice == "3":
                    # Output Settings submenu
                    try:
                        handle_output_settings()
                    except Exception as e:
                        print(f"[red]Error in output settings: {e}[/red]")
                        continue
                        
                elif choice == "4":
                    print("Exiting.")
                    break
                else:
                    print("Invalid input. Please enter a number between 1 and 4.")
                    
            except Exception as e:
                print(f"[red]Error in main menu: {e}[/red]")
                continue
    
    except KeyboardInterrupt:
        print(Text("\n\nExiting...", style=None))
    except Exception as e:
        print(Text(f"\n\nUnexpected error: {e}", style="red"))
        print("[yellow]Please report this error if it persists.[/yellow]")
        sys.exit(1)

if __name__ == "__main__":
    main()