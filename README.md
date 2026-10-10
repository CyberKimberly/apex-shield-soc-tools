# Apex Shield SOC Tools

Apex Shield SOC Tools is a security automation toolkit built for Security Operations Center (SOC) work. It contains three scripts, one each in Python, PowerShell, and Bash, that automate routine tasks a SOC analyst would otherwise do by hand: analyzing authentication logs for attacks, auditing the security posture of a Windows host, and capturing a security snapshot of a Linux host. Each script produces a clear, timestamped report that an analyst can review, compare over time, or attach to an investigation. This project was built as part of the Coding Temple AI Cybersecurity Bootcamp (Module 7: Scripting and Automation for Cybersecurity).

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
Reads a Linux authentication log, counts failed login attempts by source IP address, and ranks the top offenders. It flags suspicious IPs in two ways: any IP with 3 or more failures is marked for investigation, and Z-score statistical analysis (Z > 2.0) flags IPs whose failure counts are unusually high compared to the rest, a common sign of brute-force attacks. Results are written to a report file, and a sample log (`sample_auth.log`) is included so the script can be tested safely without real system data.

### PowerShell: Windows Security Report (`powershell/security_report.ps1`)
Audits a Windows host and saves the results to a timestamped report. It covers disk space, running services, automatic-start services that are stopped, and local user accounts, and it detects when the host is a domain controller. The report gives an analyst a quick baseline of a Windows machine's health and security posture.

### Bash: Linux Security Snapshot (`bash/security_snapshot.sh`)
Captures a point-in-time security snapshot of a Linux host, covering recent and failed logins, the status of key security services, listening ports and established network connections, and shell scripts modified in the last 7 days. Each run creates a uniquely timestamped report, so earlier snapshots are never overwritten and can be compared to spot changes.

## How to Run

### Python
Requires Python 3.
```bash
cd python
python3 log_analyzer.py sample_auth.log
```
Optional flags:
- `--output report.txt` (or `-o`) saves the report to a custom file (default: `analysis_report.txt`)
- `--verbose` (or `-v`) lists every failed login entry, not just the summary

Run `python3 log_analyzer.py --help` to see all options.

### PowerShell
Run in PowerShell as Administrator on Windows.
```powershell
cd powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\security_report.ps1
```
The execution policy change only applies to the current PowerShell window. The report is saved as `security_report_<timestamp>.txt`.

### Bash
Run on Linux (tested on Kali Linux).
```bash
cd bash
chmod +x security_snapshot.sh
./security_snapshot.sh
```
Reports are saved to `~/security_reports/`. Running with `sudo` adds process names for all network connections and includes `/root` in the script search.

## Skills Demonstrated

- **Security automation:** scripting repetitive SOC tasks in three languages across Windows and Linux
- **Log analysis and anomaly detection:** parsing authentication logs and applying threshold and Z-score analysis to separate attacks from normal noise
- **Host-based investigation:** auditing services, user accounts, logins, network connections, and file changes for signs of compromise
- **Threat awareness:** connecting findings to attacker techniques, such as disabled security tools (MITRE ATT&CK T1562.001) and scripts dropped in world-writable directories
- **Defensive scripting:** input validation, error handling, and fallbacks so reports stay accurate when data is unavailable
- **Security reporting:** consistent, timestamped reports readable by technical and non-technical audiences
- **Version control:** managing the project with Git and GitHub using small, descriptive commits

## Author

KC ([CyberKimberly](https://github.com/CyberKimberly))

