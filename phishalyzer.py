import argparse
import os
from analyzer import parser
from analyzer import header_analyzer
from analyzer import ioc_extractor
from analyzer import url_extractor
from rich import print
from rich.text import Text

API_KEY_FILE = os.path.expanduser("~/.phishalyzer_vt_api_key")

output_mode = "fanged"  # default output mode

def get_saved_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as f:
            key = f.read().strip()
            if key:
                return key
    return None

def save_api_key(key: str):
    with open(API_KEY_FILE, "w") as f:
        f.write(key.strip())

def prompt_api_key_menu():
    saved_key = get_saved_api_key()
    if saved_key:
        while True:
            print("\nVirusTotal API Settings:")
            print("1: View current API key")
            print("2: Delete API key")
            print("3: Enter a new API key")
            print("4: Return to main menu")
            choice = input("Enter option [1-4]: ").strip()
            if choice == "1":
                print(f"Saved API Key: {saved_key}\n")
            elif choice == "2":
                try:
                    os.remove(API_KEY_FILE)
                    print("Saved API key deleted.\n")
                    saved_key = None
                except FileNotFoundError:
                    print("No saved API key found to delete.\n")
            elif choice == "3":
                print(
                    "Enter your [blue]VirusTotal[/blue] API key "
                    "(create an account at https://virustotal.com/gui/my-apikey), or press Enter to cancel:"
                )
                user_key = input().strip()
                if user_key:
                    save_api_key(user_key)
                    print("API key saved for future runs.\n")
                    saved_key = user_key
                else:
                    print("No changes made to API key.\n")
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
        user_key = input().strip()
        if user_key:
            save_api_key(user_key)
            print("API key saved for future runs.\n")
            return user_key
        else:
            print("Continuing without VirusTotal API key. IP reputation checks will be skipped.\n")
            return None
    return saved_key

def print_current_config(vt_api_key, output_mode):
    api_status = Text()
    if vt_api_key:
        api_status.append("with API key", style="blue")
    else:
        api_status.append("without API key", style="red")

    output_status = Text()
    if output_mode == "fanged":
        output_status.append("fanged", style="red")
    else:
        output_status.append("defanged", style="green")

    # Compose the full message as Text to keep colors
    print(Text("Current configuration: Running ") + api_status + Text(" and ") + output_status + Text(" output format.\n"))

def run_analysis(file_path, vt_api_key):
    msg_obj, filetype = parser.load_email(file_path)
    print(f"Detected file type: {filetype}")
    print(f"Subject: {msg_obj.get('Subject')}\n")

    header_analyzer.analyze_headers(msg_obj)

    print()  # Blank line between header analysis and IP analysis
    ioc_extractor.print_centered_header("IP ADDRESS ANALYSIS")
    ioc_extractor.analyze_ips(msg_obj, api_key=vt_api_key)

    print()  # Blank line between IP and URL analysis
    url_extractor.analyze_urls(msg_obj, api_key=vt_api_key)

def main():
    global output_mode
    parser_args = argparse.ArgumentParser(description="Phishing Email Analyzer")
    parser_args.add_argument("file_path", nargs="?", help="Path to .eml or .msg file")
    args = parser_args.parse_args()

    file_path_arg = args.file_path

    vt_api_key = get_saved_api_key()

    while True:
        print("\nMain Menu:")
        print("1: Start script [ENTER]")
        print("2: VirusTotal API Settings")
        print("3: Output Settings")
        print("4: Exit")

        print_current_config(vt_api_key, output_mode)

        choice = input("Enter option [1-4] (default 1): ").strip()

        if choice == "" or choice == "1":
            # Start script
            if not file_path_arg:
                file_path = input("Enter path to .eml or .msg file: ").strip()
            else:
                file_path = file_path_arg

            # Refresh API key each run to respect possible user changes
            vt_api_key = get_saved_api_key()
            run_analysis(file_path, vt_api_key)
            # After run, return to main menu
        elif choice == "2":
            # VirusTotal API Settings submenu
            vt_api_key = prompt_api_key_menu()
        elif choice == "3":
            # Output Settings submenu
            while True:
                print("\nOutput Settings:")
                print("1: Fanged")
                print("2: Defanged")
                print("3: Return to main menu")

                submenu_choice = input("Enter option [1-3]: ").strip()

                if submenu_choice == "1":
                    output_mode = "fanged"
                    print("Output mode set to [red]Fanged[/red].")
                    break
                elif submenu_choice == "2":
                    output_mode = "defanged"
                    print("Output mode set to [green]Defanged[/green].")
                    break
                elif submenu_choice == "3":
                    break
                else:
                    print("Invalid input. Please enter 1, 2, or 3.")
        elif choice == "4":
            print("Exiting.")
            break
        else:
            print("Invalid input. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main()
