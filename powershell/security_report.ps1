# security_report.ps1
# Apex Shield SOC Tools -- Windows Security Snapshot
# Module 7 Project
##
# Collects: Disk space, running services, local user accounts
# Output: Timestamped .txt file in C:\SecurityReports\
#
# Run as Administrator for complete data

# --- Configuration ---
$reportFolder = "C:\SecurityReports"
$timestamp    = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportFile   = "$reportFolder\security_report_$timestamp.txt"

# Create the output folder if it doesn't exist
if (-not (Test-Path $reportFolder)) {
    New-Item -ItemType Directory -Path $reportFolder | Out-Null
    Write-Host "[+] Created folder: $reportFolder"
}

# Helper function: write a section header to the report
function Write-Section {
    param([string]$Title)
    Add-Content -Path $reportFile -Value ""
    Add-Content -Path $reportFile -Value ("=" * 55)
    Add-Content -Path $reportFile -Value "  $Title"
    Add-Content -Path $reportFile -Value ("=" * 55)
}

# Report header
$header = @"
=======================================================
  APEX SHIELD SOC -- WINDOWS SECURITY REPORT
=======================================================
  Generated : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Computer  : $env:COMPUTERNAME
  User      : $env:USERNAME
=======================================================
"@
Set-Content -Path $reportFile -Value $header
Write-Host "[*] Starting security report..."
Write-Host "[*] Output: $reportFile"