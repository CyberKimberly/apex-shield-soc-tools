# log_analyzer.py
# Apex Shield SOC Tools -- Log Analysis Utility
# Module 7 Project
# Reads an authentication log file, identifies failed login attempts,
# and generates a formatted analysis report.
#
# Usage: python3 log_analyzer.py [logfile]
#        (defaults to sample_auth.log if no file is given)
# Output: analysis_report.txt

import re                       # Regular expressions -- for IP address extraction
from collections import Counter  # Counter -- for counting IP occurrences
from datetime import datetime   # datetime -- for timestamping the report
import sys                      # sys -- for reading command-line arguments


def read_log_file(filepath):
    """
    Read a log file and return all lines as a list of strings.
    Returns an empty list and prints an error if the file cannot be read.
    """
    lines = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                clean = line.strip()
                if clean:
                    lines.append(clean)
    except FileNotFoundError:
        print(f"[!] ERROR: Log file not found: {filepath}")
        print(f"[!] Make sure {filepath} exists in the same folder as this script.")
    except PermissionError:
        print(f"[!] ERROR: Permission denied reading: {filepath}")
    return lines


def find_failed_logins(lines):
    """
    Filter a list of log lines to return only failed login attempts.

    Checks for two patterns:
    - Lines containing "Failed" (SSH failed password attempts)
    - Lines containing "authentication failure" (sudo/PAM failures)

    Parameters:
        lines (list): All log lines to search through

    Returns:
        list: Only the lines that represent failed logins
    """
    failed = []
    for line in lines:
        if "Failed" in line or "authentication failure" in line.lower():
            failed.append(line)
    return failed


def extract_ip_addresses(lines):
    """
    Extract all IP addresses from a list of log lines.

    Uses a regular expression to match IPv4 addresses in the format
    X.X.X.X where each X is 1-3 digits.

    Parameters:
        lines (list): Log lines to search for IP addresses

    Returns:
        list: All IP addresses found (may contain duplicates)
    """
    # This pattern matches IPv4 addresses: four groups of 1-3 digits
    # separated by dots, surrounded by word boundaries
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    all_ips = []
    for line in lines:
        matches = ip_pattern.findall(line)   # Returns a list of all matches in the line
        all_ips.extend(matches)              # extend adds each item, not the list as one item

    return all_ips


def generate_report(failed_logins, ip_counts, output_file, log_file):
    """
    Write a formatted analysis report to a text file.

    Parameters:
        failed_logins (list): All failed login log lines
        ip_counts (Counter): IP addresses and their failure counts
        output_file (str): Path where the report should be saved
        log_file (str): Name of the log file that was analyzed

    Returns:
        None (creates the report file as a side effect)
    """
    # Get current timestamp for the report header
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_file, "w") as f:
        # Report header
        f.write("=" * 55 + "\n")
        f.write("  APEX SHIELD SOC -- FAILED LOGIN ANALYSIS REPORT\n")
        f.write("=" * 55 + "\n")
        f.write(f"  Generated: {timestamp}\n")
        f.write(f"  Log File:  {log_file}\n")
        f.write("=" * 55 + "\n\n")

        # Summary section
        f.write("SUMMARY\n")
        f.write("-" * 30 + "\n")
        f.write(f"Total failed login attempts: {len(failed_logins)}\n")
        f.write(f"Unique source IPs: {len(ip_counts)}\n\n")

        # Top IPs section
        f.write("TOP SOURCE IP ADDRESSES\n")
        f.write("-" * 30 + "\n")
        for ip, count in ip_counts.most_common():
            # Flag IPs with 3 or more attempts
            flag = "  <-- INVESTIGATE" if count >= 3 else ""
            f.write(f"  {ip:<20} {count:>3} attempts{flag}\n")

        # Full failed login log
        f.write("\n\nFULL FAILED LOGIN LOG\n")
        f.write("-" * 30 + "\n")
        for entry in failed_logins:
            f.write(f"  {entry}\n")

    print(f"[+] Report written to: {output_file}")


def main():
    """
    Main execution function.
    Orchestrates the log analysis workflow.
    """
    # Configuration -- use the filename from the command line if one was
    # given, otherwise fall back to the default sample log
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = "sample_auth.log"
    output_file = "analysis_report.txt"

    print("\n" + "=" * 55)
    print("  APEX SHIELD -- LOG ANALYZER")
    print("=" * 55)

    # Step 1: Load the log file
    print(f"\n[*] Reading log file: {log_file}")
    lines = read_log_file(log_file)

    if not lines:                               # If the list is empty (file not found)
        print("[!] No log data loaded. Exiting.")
        return                                  # Exit main() early

    print(f"[+] Loaded {len(lines)} log entries.")

    # Step 2: Find failed logins
    print("\n[*] Scanning for failed login attempts...")
    failed = find_failed_logins(lines)
    print(f"[+] Found {len(failed)} failed login attempts.")

    # Step 3: Extract IP addresses
    print("\n[*] Extracting source IP addresses...")
    ips = extract_ip_addresses(failed)
    ip_counts = Counter(ips)
    print(f"[+] Found {len(ip_counts)} unique source IP addresses.")

    # Step 4: Show summary to terminal
    print("\n[*] Top source IPs:")
    for ip, count in ip_counts.most_common(5):
        flag = "  <-- INVESTIGATE" if count >= 3 else ""
        print(f"    {ip:<20} {count:>3} failures{flag}")

    # Step 5: Generate the report
    print(f"\n[*] Writing report to: {output_file}")
    generate_report(failed, ip_counts, output_file, log_file)

    print("\n[+] Analysis complete.")
    print("=" * 55 + "\n")


# This block runs main() when the script is executed directly
# It does NOT run when this file is imported as a module
if __name__ == "__main__":
    main()