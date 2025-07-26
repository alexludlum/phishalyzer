import argparse
import os
from analyzer import parser
from analyzer import header_analyzer
from analyzer import ioc_extractor
from rich import print

API_KEY_FILE = os.path.expanduser("~/.phishalyzer_vt_api_key")

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

def prompt_api_key():
    saved_key = get_saved_api_key()
    if saved_key:
        print(f"Using saved VirusTotal API key.")
        while True:
            print("Choose an option:")
            print("1: Continue with the saved API key.")
            print("2: View the current API key.")
            print("3: Enter a new key.")
            print("4: Delete the current API key.")
            print("5: Continue without an API key.")
            choice = input("Enter option [1-5] (default 1): ").strip()

            if choice == "" or choice == "1":
                return saved_key
            elif choice == "2":
                print(f"Saved API Key: {saved_key}\n")
            elif choice == "3":
                # Prompt for new key
                print(
                    "Enter your [blue]VirusTotal[/blue] API key "
                    "(create an account at https://virustotal.com/gui/my-apikey), or press Enter to return to options:"
                )
                user_key = input().strip()
                if user_key:
                    save_api_key(user_key)
                    print("API key saved for future runs.\n")
                    return user_key
                else:
                    print("Returning to options menu.\n")
                    continue  # Go back to options menu
            elif choice == "4":
                try:
                    os.remove(API_KEY_FILE)
                    print("Saved API key deleted.\n")
                except FileNotFoundError:
                    print("No saved API key found to delete.\n")
                break
            elif choice == "5":
                print("Continuing without VirusTotal API key. IP reputation checks will be skipped.\n")
                return None
            else:
                print("Invalid input. Please enter a number between 1 and 5.")

    # No saved key or after deleting:
    print(
        "Enter your [blue]VirusTotal[/blue] API key "
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

def main():
    parser_args = argparse.ArgumentParser(description="Phishing Email Analyzer")
    parser_args.add_argument("file_path", nargs="?", help="Path to .eml or .msg file")
    args = parser_args.parse_args()

    if not args.file_path:
        print("⚠️ No file path provided.")
        file_path = input("Enter path to .eml or .msg file: ").strip()
    else:
        file_path = args.file_path

    vt_api_key = prompt_api_key()

    msg_obj, filetype = parser.load_email(file_path)
    print(f"Detected file type: {filetype}")
    print(f"Subject: {msg_obj.get('Subject')}\n")

    header_analyzer.analyze_headers(msg_obj)

    print()  # Blank line between header analysis and IP analysis
    ioc_extractor.print_centered_header("IP ADDRESS ANALYSIS")
    ioc_extractor.analyze_ips(msg_obj, vt_api_key)

if __name__ == "__main__":
    main()
