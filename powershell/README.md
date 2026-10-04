# PowerShell Security Scripts

## security_report.ps1

Windows security snapshot script. Collects disk space, running services,
stopped auto-start services, and user accounts. Saves a timestamped report
to `C:\SecurityReports\`.

### What it checks

- **Disk space**: total, used, and free space per drive, with a warning below 15% free
- **Running services**: all running services and their start mode
- **Stopped auto-start services**: services set to start automatically that are not running
- **User accounts**: enabled/disabled status, last logon, and password expiry

### Domain controller detection

The script checks the server's role before collecting user accounts.
Domain controllers have no local accounts, so `Get-LocalUser` fails on them.

- **Domain controller**: uses `Get-ADUser` to list domain accounts
- **Member or standalone server**: uses `Get-LocalUser` to list local accounts

### How to run

Run PowerShell as Administrator from the repository root:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process
.\powershell\security_report.ps1
```

### Notes

- AD's `LastLogonDate` can lag by 9–14 days. Check Security event 4624 for exact logon times.
- Accounts set to "must change password at next logon" show **Pwd Expires: Never**.
  Verify with `Get-ADUser <name> -Properties PasswordNeverExpires, PasswordLastSet`.
- Reports contain system details and are saved outside the repository on purpose.