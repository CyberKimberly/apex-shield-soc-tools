# Python Security Scripts

## log_analyzer.py

A security log analysis tool that reads authentication logs, identifies
failed login attempts, and generates a formatted report.

### What It Does

- Reads a text-based security log file (SSH/sudo authentication logs)
- Identifies lines containing failed login attempts using keyword matching
- Extracts source IP addresses using regular expressions
- Counts and ranks IPs by number of failed attempts
- Flags IPs with 3 or more failures for investigation
- Applies Z-score statistical analysis (Z > 2.0) to flag IPs whose failure counts are unusually high compared to the rest, catching outliers a fixed threshold might miss
- Writes a formatted analysis report to `analysis_report.txt`
- Accepts command-line options for input file, output file, and verbose mode
- Validates that the log file exists before processing

### Usage

```bash
cd python
python3 log_analyzer.py                              # analyze sample_auth.log (default)
python3 log_analyzer.py /path/to/auth.log            # analyze any log file
python3 log_analyzer.py auth.log -o my_report.txt    # save report to a custom file
python3 log_analyzer.py -v                           # verbose: list every failed login
python3 log_analyzer.py --help                       # show all options
```

If the log file doesn't exist, the script prints a clear error and exits without processing.

### Note

`sample_auth.log` contains fictional test data for demonstration purposes.

### Sample Output

```
SUMMARY
------------------------------
Total failed login attempts: 11
Unique source IPs: 4

TOP SOURCE IP ADDRESSES
------------------------------
  192.168.40.10          4 attempts  <-- INVESTIGATE
  185.220.101.42         4 attempts  <-- INVESTIGATE
  10.0.0.55              1 attempts
  192.168.1.200          1 attempts
```