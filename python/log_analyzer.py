# log_analyzer.py
# Apex Shield SOC Tools -- Log Analysis Utility
# Module 7 Project
# Reads an authentication log file, identifies failed login attempts,
# and generates a formatted analysis report.
#
# Usage: python3 log_analyzer.py [log_file] [--output FILE] [--verbose]
#        log_file defaults to sample_auth.log if not given
# Output: analysis_report.txt (or the path given with --output)

import re                          # Regular expressions -- for IP address extraction
from collections import Counter    # Counter -- for counting IP occurrences
from datetime import datetime      # datetime -- for timestamping the report
import sys                         # sys -- exit codes on error
import argparse                    # argparse -- command-line argument parsing
import os                          # os -- file existence checks
import statistics                  # statistics -- mean/stdev for anomaly detection

# --- Detection thresholds ---
Z_THRESHOLD = 2.0              # Z-score cutoff for statistical outliers
INVESTIGATE_THRESHOLD = 3      # Failed attempts that trigger an INVESTIGATE flag


def parse_arguments():
    """
        Parse command-line arguments.

        Usage: python3 log_analyzer.py [log_file] [--output report.txt] [--verbose]

        Returns:
            argparse.Namespace: Parsed arguments (log_file, output, verbose)
    """
    parser = argparse.ArgumentParser(
        description="Apex Shield SOC Log Analyzer -- Detect failed login patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 log_analyzer.py auth.log --output report.txt"
    )

    parser.add_argument(
        "log_file",
        nargs="?",
        default="sample_auth.log",
        help="Path to the log file to analyze (default: sample_auth.log)"
    )

    parser.add_argument(
        "--output", "-o",
        default="analysis_report.txt",
        help="Output report file path (default: analysis_report.txt)"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",            #flag: True if present, False is absent
        help="Show detailed output including all failed login entries"
    )

    return parser.parse_args()


def read_log_file(filepath):
    """
    Read a log file and return all lines as a list of strings.
    Returns an empty list and prints an error if the file cannot be read.

    Parameters:
        filepath (str): Path to the log file

    Returns:
        list: Non-empty lines with whitespace stripped
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


def flag_anomalies(ip_counts, z_threshold=Z_THRESHOLD):
    """
    Identify IP addresses whose failure count is statistically unusual
    compared to the overall distribution.

    Uses Z-score: how many standard deviations a value is from the mean.
    A Z-score above z_threshold indicates a statistical outlier.

    Parameters:
        ip_counts (Counter): IP addresses and their failure counts
        z_threshold (float): Z-score cutoff for flagging (default: Z_THRESHOLD)

    Returns:
        list: Tuples of (ip, count, z_score) for anomalous IPs
    """
    if len(ip_counts) < 2:
        return []   # Need at least 2 data points for statistics

    counts = list(ip_counts.values())   # Just the numbers
    mean   = statistics.mean(counts)
    stdev  = statistics.stdev(counts)   # Sample standard deviation

    if stdev == 0:
        return []   # All counts are equal: no anomaly possible

    anomalies = []
    for ip, count in ip_counts.items():
        z_score = (count - mean) / stdev
        if z_score > z_threshold:
            anomalies.append((ip, count, round(z_score, 2)))

    return sorted(anomalies, key=lambda x: x[2], reverse=True)


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
            # Flag IPs at or above INVESTIGATE_THRESHOLD
            flag = "  <-- INVESTIGATE" if count >= INVESTIGATE_THRESHOLD else ""
            f.write(f"  {ip:<20} {count:>3} attempts{flag}\n")

        # Statistical anomaly section
        f.write(f"\nSTATISTICAL ANOMALY DETECTION (Z-score > {Z_THRESHOLD})\n")
        f.write("-" * 30 + "\n")
        anomalies = flag_anomalies(ip_counts)
        if anomalies:
            for ip, count, z_score in anomalies:
                f.write(f"  {ip:<20} {count:>3} attempts  Z={z_score}  <-- OUTLIER\n")
        else:
            f.write(f"  No statistically unusual IPs ({len(ip_counts)} IPs analyzed).\n")
            if len(ip_counts) < 6:
               f.write(f"  Note: fewer than 6 IPs; Z > {Z_THRESHOLD} is not reachable at this sample size.\n")

        # Full failed login log
        f.write("\n\nFULL FAILED LOGIN LOG\n")
        f.write("-" * 30 + "\n")
        for entry in failed_logins:
            f.write(f"  {entry}\n")

    print(f"[+] Report written to: {output_file}")


def main():
    """
    Run the log analysis from the command line.

    Steps: parse arguments, validate the input file, read and filter
    the log, count failures per IP, flag anomalies, and write the report.
    Exits with code 1 if the file is missing or empty.
    """
    args = parse_arguments()

    log_file    = args.log_file
    output_file = args.output
    verbose     = args.verbose

    # Validate input file exists
    if not os.path.isfile(log_file):
        print(f"[!] Error: File not found: {log_file}")
        print("[!] Run with --help for usage.")
        sys.exit(1)                # Non-zero exit code signals failure to the shell 
    
    print(f"\n[*] Log file: {log_file}")
    print(f"[*] Output:   {output_file}")

    lines = read_log_file(log_file)
    if not lines:
        print("[!] No log data loaded. Exiting.")
        sys.exit(1)

    failed = find_failed_logins(lines)          # Keep only failed-login lines
    ips    = extract_ip_addresses(failed)       # Pull the IPs from those lines
    ip_counts = Counter(ips)                    # Tally failures per IP

    if verbose:
        print(f"\n[*] All failed login entries ({len(failed)}):")
        for entry in failed:
            print(f"    {entry}")

    print(f"\n[*] Top IPs:")
    for ip, count in ip_counts.most_common(5):
        flag = " <-- INVESTIGATE" if count >= INVESTIGATE_THRESHOLD else ""
        print(f"    {ip:<20} {count:>3} failures{flag}")

    print(f"\n[*] Statistical anomalies (Z > {Z_THRESHOLD}):")
    anomalies = flag_anomalies(ip_counts)
    if anomalies:
        for ip, count, z_score in anomalies:
            print(f"    {ip:<20} {count:>3} failures  Z={z_score} <-- OUTLIER")
    else:
        print(f"    None detected ({len(ip_counts)} IPs analyzed)")

    generate_report(failed_logins=failed, ip_counts=ip_counts, output_file=output_file, log_file=log_file)
    


# This block runs main() when the script is executed directly
# It does NOT run when this file is imported as a module
if __name__ == "__main__":
    main()
