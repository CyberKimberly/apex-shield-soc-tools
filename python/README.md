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
- Writes a formatted analysis report to `analysis_report.txt`

### Usage

```bash
cd python
python3 log_analyzer.py # analyzes sample_auth.log
python3 log_analyzer.py /path/to/auth.log  # analyzes any log file
```

Make sure `sample_auth.log` is in the same directory as the script.

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