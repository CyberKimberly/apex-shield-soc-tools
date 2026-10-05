# security_snapshot.sh

Linux security snapshot tool for SOC triage. Collects key security data from a Linux host and saves it to a timestamped report.

## What it collects

| Section | Command | Purpose |
|---|---|---|
| Login history | `last`, `lastb` | Recent logins and failed login attempts |
| Service status | `systemctl is-active` | Whether ssh, cron, wazuh-agent, and ufw are running |
| Network connections | `ss -tlnp`, `ss -tunp` | Listening ports and established connections |
| Recent shell scripts | `find` | `.sh` files modified in /home, /root, and /tmp |

## Usage

```bash
chmod +x security_snapshot.sh
./security_snapshot.sh
```

Reports are saved to `~/security_reports/snapshot_YYYY-MM-DD_HH-MM-SS.txt`.

Run with `sudo` for full results. Without root, failed logins (`lastb`) and process names in `ss` output are unavailable.

## Scheduling with cron

Runs weekdays at 6:00 AM:
```
0 6 * * 1-5 /home/kaliuser/apex-shield-soc-tools/bash/security_snapshot.sh >> /home/kaliuser/security_reports/cron_snapshot.log 2>&1
```

## Known limitations

- The script check uses `-newer /etc/passwd`, which compares against the last account change, not a fixed 7-day window. `-mtime -7` would match the section heading.
- On newer Kali releases, `last` may return no output if login records use the wtmpdb format. Errors are hidden by `2>/dev/null`.

## Tested on

Kali Linux (ARM64) in UTM. Coding Temple AI Cybersecurity Bootcamp, Module 7.
