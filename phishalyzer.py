import argparse
import os
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
    # Calculate padding to make all headers the same width (50 characters total)
    total_width = 50
    title_with_spaces = f" {title.upper()} "
    padding_needed = total_width - len(title_with_spaces)
    left_padding = padding_needed // 2
    right_padding = padding_needed - left_padding
    
    header_line = "=" * left_padding + title_with_spaces + "=" * right_padding
    print(f"\n{header_line}\n")

def get_saved_output_mode():
    """Get saved output mode from file."""
    if os.path.exists(OUTPUT_MODE_FILE):
        try:
            with open(OUTPUT_MODE_FILE, "r") as f:
                mode = f.read().strip()
                if mode in ['fanged', 'defanged']:
                    return mode
        except Exception as e:
            print(f"[yellow]Warning: Could not read output mode file: {e}[/yellow]")
    return "fanged"  # default

def save_output_mode(mode: str):
    """Save output mode to file."""
    try:
        with open(OUTPUT_MODE_FILE, "w") as f:
            f.write(mode.strip())
    except Exception as e:
        print(f"[red]Error saving output mode: {e}[/red]")

def get_saved_api_key():
    """Get saved VirusTotal API key from file."""
    if os.path.exists(API_KEY_FILE):
        try:
            with open(API_KEY_FILE, "r") as f:
                key = f.read().strip()
                if key:
                    return key
        except Exception as e:
            print(f"[yellow]Warning: Could not read API key file: {e}[/yellow]")
    return None

def save_api_key(key: str):
    """Save VirusTotal API key to file."""
    try:
        with open(API_KEY_FILE, "w") as f:
            f.write(key.strip())
    except Exception as e:
        print(f"[red]Error saving API key: {e}[/red]")

def prompt_api_key_menu():
    """Handle VirusTotal API key management menu."""
    saved_key = get_saved_api_key()
    if saved_key:
        while True:
            print("\nVirusTotal API Settings:")
            print("1: View current API key")
            print("2: Delete API key")
            print("3: Enter a new API key")
            print("4: Return to main menu")
            
            try:
                choice = input("Enter option [1-4]: ").strip()
            except KeyboardInterrupt:
                print(Text("\n\nReturning to main menu...", style=None))
                return saved_key
                
            if choice == "1":
                print(f"[blue]Saved API Key:[/blue] {saved_key}\n")
            elif choice == "2":
                try:
                    os.remove(API_KEY_FILE)
                    print(Text("Saved API key deleted.\n", style="red"))
                    saved_key = None
                except FileNotFoundError:
                    print(Text("No saved API key found to delete.\n", style="orange3"))
            elif choice == "3":
                print(
                    "Enter your [blue]VirusTotal[/blue] API key "
                    "(create an account at https://virustotal.com/gui/my-apikey), or press Enter to cancel:"
                )
                try:
                    user_key = input().strip()
                    if user_key:
                        save_api_key(user_key)
                        print(Text("API key saved for future runs.\n", style="green"))
                        saved_key = user_key
                    else:
                        print(Text("No changes made to API key.\n", style="yellow"))
                except KeyboardInterrupt:
                    print(Text("\n\nNo changes made to API key.\n", style="yellow"))
            elif choice == "4":
                return saved_key
            else:
                print("Invalid input. Please enter a number between 1 and 4.")
    else:
        print(
            "No VirusTotal API key saved."
            "\nEnter your [blue]VirusTotal[/blue] API key "
            "(create an account at https://virustotal.com/gui/my-apikey), or press Enter to skip:"
        )
        try:
            user_key = input().strip()
            if user_key:
                save_api_key(user_key)
                print(Text("API key saved for future runs.\n", style="green"))
                return user_key
            else:
                print(Text("Continuing without VirusTotal API key. Reputation checks will be skipped.\n", style="yellow"))
                return None
        except KeyboardInterrupt:
            print(Text("\n\nContinuing without VirusTotal API key. Reputation checks will be skipped.\n", style="yellow"))
            return None
    return saved_key

def print_current_config(vt_api_key, output_mode):
    """Display current configuration status."""
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

def run_analysis(file_path, vt_api_key):
    """Run complete email analysis."""
    try:
        
        # Show defanging status if enabled
        if output_mode == "defanged":
            status_text = Text()
            status_text.append("DEFANGED OUTPUT MODE: ", style="blue bold")
            status_text.append("URLs and IPs are displayed in safe format", style="green")
            print(status_text)
            print()
        
        msg_obj, filetype = parser.load_email(file_path)
        print(f"Detected file type: {filetype}")
        
        subject_text = Text("Subject: ")
        subject_text.append(msg_obj.get('Subject', 'No Subject'))
        print(subject_text)
        print()

        # Header analysis
        print_section_header("EMAIL HEADER ANALYSIS")
        header_analyzer.analyze_headers(msg_obj)
        print()

        # IP analysis
        print_section_header("IP ADDRESS ANALYSIS")
        ioc_extractor.analyze_ips(msg_obj, api_key=vt_api_key)
        print()

        # URL analysis
        print_section_header("URL ANALYSIS")
        url_extractor.analyze_urls(msg_obj, api_key=vt_api_key)
        print()

        # Attachment analysis
        print_section_header("ATTACHMENT ANALYSIS")
        attachment_analyzer.analyze_attachments(msg_obj, api_key=vt_api_key)
        
    except FileNotFoundError:
        print(Text(f"Error: File '{file_path}' not found.", style="red"))
    except Exception as e:
        print(Text(f"Error during analysis: {str(e)}", style="red"))

def handle_output_settings():
    """Handle output settings submenu."""
    global output_mode
    
    while True:
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

        try:
            submenu_choice = input("Enter option [1-3]: ").strip()
        except KeyboardInterrupt:
            print(Text("\n\nReturning to main menu...", style=None))
            break

        if submenu_choice == "1":
            output_mode = "fanged"
            save_output_mode(output_mode)  # Save the setting immediately
            print("Output mode set to [red]Fanged[/red] and saved.")
            break
        elif submenu_choice == "2":
            output_mode = "defanged"
            save_output_mode(output_mode)  # Save the setting immediately
            print("Output mode set to [green]Defanged[/green] and saved.")
            break
        elif submenu_choice == "3":
            break
        else:
            print("Invalid input. Please enter 1, 2, or 3.")

def main():
    """Main application entry point."""
    global output_mode
    parser_args = argparse.ArgumentParser(description="Phishing Email Analyzer")
    parser_args.add_argument("file_path", nargs="?", help="Path to .eml or .msg file")
    args = parser_args.parse_args()

    file_path_arg = args.file_path
    
    # Load saved settings at startup
    vt_api_key = get_saved_api_key()
    output_mode = get_saved_output_mode()  # This will now properly load the saved mode

    try:
        while True:
            print("\nMain Menu:")
            print("1: Start script [ENTER]")
            print("2: VirusTotal API Settings")
            print("3: Output Settings")
            print("4: Exit")

            print_current_config(vt_api_key, output_mode)

            try:
                choice = input("Enter option [1-4] (default 1): ").strip()
            except KeyboardInterrupt:
                print(Text("\n\nExiting...", style=None))
                break

            if choice == "" or choice == "1":
                # Start script
                if not file_path_arg:
                    try:
                        file_path = input("Enter path to .eml or .msg file: ").strip()
                        if not file_path:
                            print("No file path provided. Returning to main menu.")
                            continue
                    except KeyboardInterrupt:
                        print(Text("\n\nOperation cancelled. Returning to main menu...", style=None))
                        continue
                else:
                    file_path = file_path_arg

                # Refresh API key each run to respect possible user changes
                vt_api_key = get_saved_api_key()
                try:
                    run_analysis(file_path, vt_api_key)
                except KeyboardInterrupt:
                    print(Text("\n\nAnalysis cancelled. Returning to main menu...", style=None))
                    continue
                # After run, return to main menu
                
            elif choice == "2":
                # VirusTotal API Settings submenu
                try:
                    vt_api_key = prompt_api_key_menu()
                except KeyboardInterrupt:
                    print(Text("\n\nReturning to main menu...", style=None))
                    continue
                    
            elif choice == "3":
                # Output Settings submenu
                try:
                    handle_output_settings()
                except KeyboardInterrupt:
                    print(Text("\n\nReturning to main menu...", style=None))
                    continue
                    
            elif choice == "4":
                print("Exiting.")
                break
            else:
                print("Invalid input. Please enter a number between 1 and 4.")
    
    except KeyboardInterrupt:
        print(Text("\n\nExiting...", style=None))
    except Exception as e:
        print(Text(f"\n\nUnexpected error: {e}", style="red"))

if __name__ == "__main__":
    main()