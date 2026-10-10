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

- On newer Kali releases, `last` may return no output because login records use the wtmpdb format. The script tries ISO timestamps, then the default format, and if both fail it writes "(login history unavailable on this system)" instead of leaving the section blank.
- The recent-scripts check uses `-mtime -7`, which relies on file modification times. A script whose timestamp was altered (for example with `touch`) can be missed, so treat this section as a quick triage aid, not proof that nothing changed.

## Tested on

Kali Linux (ARM64) in UTM. Coding Temple AI Cybersecurity Bootcamp, Module 7.
