# Windows Security Check

`Invoke-SecurityCheck.ps1` runs a quick, **read-only** check of the security basics on a Windows 10/11 machine. It rates each result **PASS / WARN / FAIL**, prints it in color in the console, and saves a timestamped HTML report.

The script does not change any system setting. It only reads information. The one file it writes is the HTML report.

## What it checks

| # | Check | How it works | Rating |
|---|-------|--------------|--------|
| 1 | **Windows Update** | Uses the Windows Update Agent COM API to search for updates that are not installed yet (search only, nothing is downloaded or installed). Reads the update history for the date of the last installed update. Only patches with a KB number count, so Store app updates and Defender signature updates are left out of that date. Falls back to `Get-HotFix`. | Pending: none = PASS, only lower-severity = WARN, any Critical/Important = FAIL. Last update: ≤ 30 days PASS, ≤ 60 WARN, older FAIL |
| 2 | **Firewall** | `Get-NetFirewallProfile -PolicyStore ActiveStore` for the Domain, Private and Public profiles (the settings in effect, including Group Policy). | Disabled = FAIL, enabled but inbound default "Allow" = WARN, enabled and blocking = PASS |
| 3 | **Microsoft Defender** | `Get-MpComputerStatus`: real-time protection, signature age, newest quick or full scan. If Defender isn't available (for example, a third-party antivirus is installed), it lists the antivirus registered with Windows Security Center. | Real-time off = FAIL. Signatures: ≤ 1 day PASS, ≤ 7 WARN, older FAIL. Last scan: ≤ 7 days PASS, ≤ 30 WARN, older or never FAIL |
| 4 | **Listening TCP ports** | `Get-NetTCPConnection -State Listen` plus the owning process name. Each port is labeled *Loopback only* (reachable only from this PC), *All interfaces* or *Specific interface*. | WARN if a high-risk service (RDP, Telnet, FTP, VNC, database servers, Redis, ...) is reachable from the network, otherwise PASS |
| 5 | **Startup programs** | Registry `Run`/`RunOnce` keys (HKLM, HKLM WOW6432Node, HKCU) and the per-user and all-users Startup folders. Shortcuts (`.lnk`) are resolved to their target. | WARN for entries that run from Temp/Downloads, use encoded PowerShell, script hosts (mshta/wscript/cscript), contain a URL, or point to a missing file. Otherwise PASS |

You can change the thresholds and the lists of risky ports and suspicious patterns at the top of the script.

## Requirements

- Windows 10 or 11
- Windows PowerShell 5.1 (built in) or PowerShell 7+
- Administrator rights are **not** required. Running as admin works too.
- Network access for the pending-update search (or use `-SkipWindowsUpdate`)

## How to run

Open PowerShell in this folder and run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SecurityCheck.ps1
```

`-ExecutionPolicy Bypass` only applies to this one PowerShell process and does not change your system's execution policy. If the file came from a download or a zip, Windows may mark it as blocked. You can unblock it once with `Unblock-File .\Invoke-SecurityCheck.ps1`.

### Options

| Parameter | Description |
|-----------|-------------|
| `-OutputPath <folder>` | Where to save the HTML report. Default: your Documents folder. The folder must already exist. |
| `-SkipWindowsUpdate` | Skip the online search for pending updates, which can take a minute or more. The last-installed-update date is still checked. |
| `-Verbose` | Show extra diagnostic messages. |

Examples:

```powershell
# Fast run without the online update search
.\Invoke-SecurityCheck.ps1 -SkipWindowsUpdate

# Save the report somewhere else
.\Invoke-SecurityCheck.ps1 -OutputPath C:\Temp
```

## Output

- **Console:** one colored line per result (green PASS, yellow WARN, red FAIL), tables of listening ports and startup entries, and a summary count at the end.
- **HTML report:** `SecurityCheck_<COMPUTERNAME>_<yyyyMMdd_HHmmss>.html` in the output folder. It has summary tiles, the full results table, and detail tables (pending updates, listening ports, startup programs). It follows your system's light or dark mode.

Reports are excluded from git by the `.gitignore` in this folder, in case you point `-OutputPath` into the repo. Reports contain details about your machine (process names, startup commands), so think before sharing them.

## Limitations

- A WARN is a prompt to review, not proof of a problem. A listening port may still be blocked by the firewall, and a flagged startup entry can be legitimate.
- Startup entries disabled in Task Manager (`StartupApproved`) are still listed.
- Other autostart locations (scheduled tasks, services, WMI subscriptions, ...) are not covered. Sysinternals **Autoruns** gives a complete view.
- Only TCP listeners are checked, not UDP.
