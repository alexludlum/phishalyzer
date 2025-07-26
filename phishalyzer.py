import argparse
from analyzer import parser
from analyzer import header_analyzer

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
    print(f"Subject: {msg_obj.get('Subject')}")
    header_analyzer.analyze_headers(msg_obj)

if __name__ == "__main__":
    main()
