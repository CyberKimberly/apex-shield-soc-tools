# Apex Shield SOC Tools

Apex Shield SOC Tools automates three routine investigation tasks that SOC analysts otherwise do by hand: spotting brute-force patterns in authentication logs, auditing a Windows host's security posture, and capturing a security snapshot of a Linux host. Each tool is a standalone script (Python, PowerShell, or Bash) that produces a clear, timestamped report an analyst can review, compare over time, or attach to an investigation. The scripts are read-only and were built and tested in a home lab as part of the Coding Temple AI Cybersecurity Bootcamp, using a fictional organization, Apex Shield, as the scenario.

## Repository Structure

```
apex-shield-soc-tools/
├── README.md
├── python/
│   ├── README.md
│   ├── log_analyzer.py
│   └── sample_auth.log
├── powershell/
│   ├── README.md
│   └── security_report.ps1
└── bash/
    ├── README.md
    └── security_snapshot.sh
```

## The Scripts

### Python: Log Analyzer (`python/log_analyzer.py`)
Reads a Linux authentication log, counts failed login attempts by source IP address, and ranks the top offenders. It flags suspicious IPs in two ways: any IP with 3 or more failures is marked for investigation, and Z-score statistical analysis (Z > 2.0) flags IPs whose failure counts are unusually high compared to the rest, a common sign of brute-force attacks. Results are written to a report file, and a sample log (`sample_auth.log`) is included so the script can be tested safely without real system data. [Full documentation](python/README.md)

### PowerShell: Windows Security Report (`powershell/security_report.ps1`)
Audits a Windows host and saves the results to a timestamped report. It covers disk space, running services, automatic-start services that are stopped, and local user accounts, and it detects when the host is a domain controller. The report gives an analyst a quick baseline of a Windows machine's health and security posture. [Full documentation](powershell/README.md)

### Bash: Linux Security Snapshot (`bash/security_snapshot.sh`)
Captures a point-in-time security snapshot of a Linux host, covering recent and failed logins, the status of key security services, listening ports and established network connections, and shell scripts modified in the last 7 days. Each run creates a uniquely timestamped report, so earlier snapshots are never overwritten and can be compared to spot changes. [Full documentation](bash/README.md)

## Sample Output

Running the log analyzer against the included sample log:

```
[*] Top IPs:
    192.168.40.10        4 failures <-- INVESTIGATE
    185.220.101.42       4 failures <-- INVESTIGATE
    10.0.0.55            1 failures
    192.168.1.200        1 failures

[*] Statistical anomalies (Z > 2.0):
    None detected (4 IPs analyzed)
[+] Report written to: analysis_report.txt
```

Both high-volume IPs are caught by the failure threshold. The Z-score check finds no outliers here because the two top IPs are tied, which shows why the script uses both methods.

## How to Run

### Getting Started
```bash
git clone https://github.com/CyberKimberly/apex-shield-soc-tools.git
cd apex-shield-soc-tools
```

| Script | Platform | Requirements |
|---|---|---|
| `log_analyzer.py` | Any OS | Python 3 |
| `security_report.ps1` | Windows | PowerShell, run as Administrator |
| `security_snapshot.sh` | Linux (systemd-based) | Bash; `sudo` optional for full results |

These scripts are read-only. Only run them on systems you own or are authorized to assess.

### Python
```bash
cd python
python3 log_analyzer.py sample_auth.log
```
Optional flags:
- `--output report.txt` (or `-o`) saves the report to a custom file (default: `analysis_report.txt`)
- `--verbose` (or `-v`) lists every failed login entry, not just the summary

Run `python3 log_analyzer.py --help` to see all options.

### PowerShell
Open PowerShell as Administrator, then from the repository root:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process
.\powershell\security_report.ps1
```
The execution policy change only applies to the current PowerShell window. Reports are saved to `C:\SecurityReports\` as `security_report_<timestamp>.txt`, outside the repository on purpose since they contain system details.

### Bash
Tested on Kali Linux.
```bash
cd bash
chmod +x security_snapshot.sh
./security_snapshot.sh
```
Reports are saved to `~/security_reports/`. Running with `sudo` adds process names for all network connections and includes `/root` in the script search. On systems that don't keep traditional login records, the login history section reports that the data is unavailable instead of leaving it blank.

## Skills Demonstrated

These scripts show that I can automate common SOC triage tasks in three languages: parsing authentication logs to flag brute-force activity with both threshold and Z-score checks, auditing Windows services and accounts, and collecting Linux login, service, network, and file-change data into timestamped reports. They also show how I work: testing on real lab systems, finding and fixing flaws in my own logic (such as telling apart a stopped security service from one that was never installed), and tracking every change in Git with clear, incremental commits.

- **Security automation:** scripting repetitive SOC tasks in Python, PowerShell, and Bash across Windows and Linux
- **Log analysis and anomaly detection:** parsing authentication logs and applying threshold and Z-score analysis to separate attacks from normal noise
- **Host-based investigation:** auditing services, user accounts, logins, network connections, and file changes for signs of compromise
- **Threat awareness:** interpreting findings in context and documenting them using MITRE ATT&CK, such as a disabled security agent (T1562.001)
- **Defensive scripting:** input validation, error handling, and fallbacks so reports stay accurate when data is unavailable
- **Security reporting:** consistent, timestamped reports readable by technical and non-technical audiences
- **Version control:** managing the project with Git and GitHub using small, descriptive commits

## Author

KC ([CyberKimberly](https://github.com/CyberKimberly))
