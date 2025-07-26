# phishalyzer.py

import argparse
import os
import time
from analyzer import parser
from analyzer import header_analyzer
from analyzer import ioc_extractor
from rich import print


def main():
    parser_args = argparse.ArgumentParser(description="Phishing Email Analyzer")
    parser_args.add_argument("file_path", nargs="?", help="Path to .eml or .msg file")
    args = parser_args.parse_args()

    if not args.file_path:
        print("⚠️ No file path provided.")
        file_path = input("Enter path to .eml or .msg file: ").strip()
    else:
        file_path = args.file_path

    msg_obj, filetype = parser.load_email(file_path)
    print(f"Detected file type: {filetype}")
    print(f"Subject: {msg_obj.get('Subject')}\n")

    header_analyzer.analyze_headers(msg_obj)

    # Add a 1 second pause with "..." for visual separation
    print("...\n")
    time.sleep(1)

    vt_api_key = os.getenv("VT_API_KEY")

    # Print IOC IP ADDRESS ANALYSIS header here, suppress in analyze_ips()
    ioc_extractor.print_centered_header("IOC IP ADDRESS ANALYSIS")

    prompt_msg = (
        "Enter your [blue]VirusTotal[/blue] API key "
        "(create an account and find it at https://virustotal.com/gui/my-apikey), or press Enter to skip:"
    )
    print(prompt_msg)
    user_input = input().strip()
    if user_input:
        vt_api_key = user_input
    else:
        if not vt_api_key:
            vt_api_key = None

    results = ioc_extractor.analyze_ips(msg_obj, vt_api_key, suppress_header=True)

    for res in results:
        if res["verdict"] == "malicious":
            print(f"One or more vendors reported this IP address as [red]MALICIOUS[/red].")
        elif res["verdict"] == "suspicious":
            print("IP address reported as suspicious by some vendors.")
        elif res["verdict"] == "benign":
            print("IP address not reported as malicious yet.")
        else:
            print("IP address reputation unknown.")


if __name__ == "__main__":
    main()
