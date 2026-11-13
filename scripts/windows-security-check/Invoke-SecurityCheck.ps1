#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only Windows security check with colored console output and an HTML report.

.DESCRIPTION
    Runs five read-only checks against the local Windows machine:
      1. Windows Update   - pending updates and date of the last installed update
      2. Firewall         - Domain / Private / Public profile status
      3. Defender         - real-time protection, signature age, last scan
      4. Listening ports  - TCP listeners with the owning process
      5. Startup programs - registry Run/RunOnce keys and Startup folders

    Every result is rated PASS / WARN / FAIL and printed in color. A summary is
    exported to a timestamped HTML file (default: the user's Documents folder).

    The script does NOT change any system setting. It only reads information.
    The only thing it writes is the HTML report.

.PARAMETER OutputPath
    Folder for the HTML report. Defaults to the current user's Documents folder.
    The folder must already exist.

.PARAMETER SkipWindowsUpdate
    Skip the online search for pending updates (it can take a minute or more and
    needs network access). The date of the last installed update is still shown.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SecurityCheck.ps1

.EXAMPLE
    .\Invoke-SecurityCheck.ps1 -SkipWindowsUpdate -OutputPath C:\Temp
#>
[CmdletBinding()]
param(
    [string]$OutputPath = [Environment]::GetFolderPath('MyDocuments'),
    [switch]$SkipWindowsUpdate
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Age thresholds in days. Age <= *PassMaxDays -> PASS, <= *WarnMaxDays -> WARN,
# anything older -> FAIL. Adjust these to match your own policy.
$Thresholds = @{
    UpdatePassMaxDays    = 30   # last installed Windows update
    UpdateWarnMaxDays    = 60
    SignaturePassMaxDays = 1    # Defender antivirus signatures
    SignatureWarnMaxDays = 7
    ScanPassMaxDays      = 7    # last completed Defender scan (quick or full)
    ScanWarnMaxDays      = 30
}

# Services that are commonly attacked when they are reachable from the network.
# A listener on one of these ports that is NOT bound to loopback becomes a WARN.
$RiskyPorts = @{
    21   = 'FTP';        23   = 'Telnet';      69    = 'TFTP'
    1433 = 'MS SQL';     3306 = 'MySQL';       3389  = 'RDP'
    5432 = 'PostgreSQL'; 5900 = 'VNC';         5985  = 'WinRM (HTTP)'
    6379 = 'Redis';      9200 = 'Elasticsearch'; 27017 = 'MongoDB'
}

# Patterns in startup commands that are often seen in malware persistence.
# A match does not prove anything is malicious; it marks the entry for review.
$SuspiciousStartupPatterns = [ordered]@{
    '\\(Local\\)?Temp\\'                      = 'runs from a Temp folder'
    '\\Downloads\\'                            = 'runs from the Downloads folder'
    'powershell(\.exe)?.*\s-(e|en|enc|encodedcommand)\s' = 'PowerShell with an encoded command'
    '\b(mshta|wscript|cscript)(\.exe)?\b'     = 'script host (mshta/wscript/cscript)'
    'https?://'                                = 'contains a URL'
    'rundll32(\.exe)?.*javascript:'            = 'rundll32 running JavaScript'
}

# ---------------------------------------------------------------------------
# Result collection and output helpers
# ---------------------------------------------------------------------------

# Every check adds one or more result rows here; the HTML report is built from it.
$script:Results = New-Object System.Collections.Generic.List[object]

# Optional detail tables (e.g. the full port list) shown below the summary in HTML.
$script:DetailTables = [ordered]@{}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=== {0} ===' -f $Title) -ForegroundColor Cyan
}

function Add-Result {
    # Records one result and prints it to the console in color.
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL')][string]$Status,
        [string]$Details = ''
    )
    $script:Results.Add([pscustomobject]@{
        Category = $Category
        Check    = $Check
        Status   = $Status
        Details  = $Details
    })

    $color = switch ($Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } }
    Write-Host ('[{0}] ' -f $Status) -ForegroundColor $color -NoNewline
    Write-Host ('{0}: {1}' -f $Check, $Details)
}

function Get-AgeStatus {
    # Maps an age in days to PASS / WARN / FAIL using the given thresholds.
    param([double]$AgeDays, [int]$PassMaxDays, [int]$WarnMaxDays)
    if ($AgeDays -le $PassMaxDays) { 'PASS' }
    elseif ($AgeDays -le $WarnMaxDays) { 'WARN' }
    else { 'FAIL' }
}

function Format-Date {
    param($Date)
    if ($null -eq $Date) { return 'n/a' }
    ([datetime]$Date).ToString('yyyy-MM-dd HH:mm')
}

# ---------------------------------------------------------------------------
# Check 1: Windows Update
# ---------------------------------------------------------------------------
# Uses the Windows Update Agent COM API (the same API the Settings app uses).
# IUpdateSearcher.Search() only SEARCHES for applicable updates. It does not
# download or install anything. QueryHistory() reads the local update history.
function Test-WindowsUpdate {
    Write-Section '1. Windows Update'
    $category = 'Windows Update'

    # --- Pending updates -----------------------------------------------------
    if ($SkipWindowsUpdate) {
        Add-Result $category 'Pending updates' 'WARN' 'Not checked (-SkipWindowsUpdate was used)'
    }
    else {
        try {
            Write-Host 'Searching for pending updates (this can take a minute)...' -ForegroundColor DarkGray
            $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
            # Not installed and not hidden by the user = updates still waiting.
            $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0")

            $pending = @(foreach ($u in $searchResult.Updates) {
                [pscustomobject]@{
                    Title    = $u.Title
                    Severity = if ($u.MsrcSeverity) { $u.MsrcSeverity } else { 'Unspecified' }
                    KB       = (@($u.KBArticleIDs) | ForEach-Object { "KB$_" }) -join ', '
                }
            })

            # Updates Microsoft rates Critical or Important are a FAIL; others a WARN.
            $important = @($pending | Where-Object { $_.Severity -in 'Critical', 'Important' })

            if ($pending.Count -eq 0) {
                Add-Result $category 'Pending updates' 'PASS' 'No pending updates'
            }
            elseif ($important.Count -gt 0) {
                Add-Result $category 'Pending updates' 'FAIL' ('{0} pending, {1} rated Critical/Important' -f $pending.Count, $important.Count)
            }
            else {
                Add-Result $category 'Pending updates' 'WARN' ('{0} pending (none rated Critical/Important)' -f $pending.Count)
            }

            if ($pending.Count -gt 0) {
                $script:DetailTables['Pending Windows updates'] = $pending
                $pending | ForEach-Object { Write-Host ('       - {0} [{1}]' -f $_.Title, $_.Severity) -ForegroundColor DarkGray }
            }
        }
        catch {
            Add-Result $category 'Pending updates' 'WARN' ('Could not query Windows Update: {0}' -f $_.Exception.Message)
        }
    }

    # --- Last installed update -------------------------------------------------
    # Only entries with a KB number count (OS, Office and security patches).
    # Microsoft Store app updates have no KB and are ignored. Defender signature
    # and platform updates install almost daily and would hide how old the last
    # real patch is, so they are excluded as well.
    $kbPattern      = 'KB\d{6,}'
    $excludePattern = 'Security Intelligence Update|Definition Update|KB2267602|KB4052623'
    $last = $null

    try {
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        if ($total -gt 0) {
            $installed = foreach ($h in $searcher.QueryHistory(0, $total)) {
                # Operation 1 = installation; ResultCode 2 = succeeded, 3 = succeeded with errors.
                if ($h.Operation -eq 1 -and ($h.ResultCode -eq 2 -or $h.ResultCode -eq 3) -and
                    $h.Title -match $kbPattern -and $h.Title -notmatch $excludePattern) {
                    [pscustomobject]@{
                        Title = $h.Title
                        # The history stores UTC; convert to local time for display.
                        Date  = ([datetime]::SpecifyKind($h.Date, 'Utc')).ToLocalTime()
                    }
                }
            }
            $last = $installed | Sort-Object Date -Descending | Select-Object -First 1
        }
    }
    catch {
        Write-Verbose ('Update history not available: {0}' -f $_.Exception.Message)
    }

    # Fallback: Get-HotFix lists installed OS patches (Win32_QuickFixEngineering).
    if (-not $last) {
        $hotfix = Get-HotFix -ErrorAction SilentlyContinue |
            Where-Object { $_.InstalledOn } |
            Sort-Object InstalledOn -Descending |
            Select-Object -First 1
        if ($hotfix) {
            $last = [pscustomobject]@{ Title = '{0} ({1})' -f $hotfix.HotFixID, $hotfix.Description; Date = $hotfix.InstalledOn }
        }
    }

    if ($last) {
        $age = ((Get-Date) - $last.Date).TotalDays
        $status = Get-AgeStatus $age $Thresholds.UpdatePassMaxDays $Thresholds.UpdateWarnMaxDays
        Add-Result $category 'Last installed update' $status ('{0} ({1:N0} days ago): {2}' -f (Format-Date $last.Date), $age, $last.Title)
    }
    else {
        Add-Result $category 'Last installed update' 'WARN' 'Could not determine the last installed update'
    }
}

# ---------------------------------------------------------------------------
# Check 2: Windows Firewall
# ---------------------------------------------------------------------------
# Reads each firewall profile from the ActiveStore, i.e. the settings that are
# actually in effect after Group Policy and local settings are merged.
#   Disabled profile                   -> FAIL
#   Enabled, but inbound default Allow -> WARN (unsolicited traffic is accepted)
#   Enabled, inbound default Block     -> PASS
function Test-Firewall {
    Write-Section '2. Windows Firewall'
    $category = 'Firewall'

    try {
        $profiles = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { $_.Name -in 'Domain', 'Private', 'Public' }

        foreach ($p in $profiles) {
            # Enabled is a GpoBoolean enum, so compare its string form.
            $enabled = ([string]$p.Enabled) -eq 'True'
            $inbound = [string]$p.DefaultInboundAction
            $check = '{0} profile' -f $p.Name

            if (-not $enabled) {
                Add-Result $category $check 'FAIL' 'Firewall is DISABLED'
            }
            elseif ($inbound -eq 'Allow') {
                Add-Result $category $check 'WARN' 'Enabled, but default inbound action is Allow'
            }
            else {
                Add-Result $category $check 'PASS' ('Enabled (default inbound: {0})' -f $inbound)
            }
        }
    }
    catch {
        Add-Result $category 'Firewall profiles' 'WARN' ('Could not read firewall profiles: {0}' -f $_.Exception.Message)
    }
}

# ---------------------------------------------------------------------------
# Check 3: Microsoft Defender Antivirus
# ---------------------------------------------------------------------------
# Get-MpComputerStatus reports Defender's current state. If a third-party
# antivirus is installed, Defender may be in passive mode or the cmdlet may
# fail; the script then lists the antivirus registered with Security Center.
function Test-Defender {
    Write-Section '3. Microsoft Defender'
    $category = 'Defender'

    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
    }
    catch {
        # Security Center knows which antivirus products are registered.
        $av = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
        $names = if ($av) { ($av.displayName | Sort-Object -Unique) -join ', ' } else { 'none found' }
        Add-Result $category 'Defender status' 'WARN' ('Defender status unavailable ({0}). Registered antivirus: {1}' -f $_.Exception.Message, $names)
        return
    }

    # Passive / EDR block mode usually means another antivirus is primary.
    if ($mp.AMRunningMode -and $mp.AMRunningMode -ne 'Normal') {
        Add-Result $category 'Running mode' 'WARN' ('Defender is in "{0}" mode; another antivirus may be the primary product' -f $mp.AMRunningMode)
    }

    # --- Real-time protection: scans files as they are opened or downloaded.
    if ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) {
        Add-Result $category 'Real-time protection' 'PASS' 'Enabled'
    }
    else {
        Add-Result $category 'Real-time protection' 'FAIL' ('Antivirus enabled: {0}, real-time protection: {1}' -f $mp.AntivirusEnabled, $mp.RealTimeProtectionEnabled)
    }

    # --- Signature age: old signatures miss new malware.
    $sigAge = [int]$mp.AntivirusSignatureAge
    $status = Get-AgeStatus $sigAge $Thresholds.SignaturePassMaxDays $Thresholds.SignatureWarnMaxDays
    Add-Result $category 'Signature age' $status ('{0} day(s) old, version {1}, updated {2}' -f $sigAge, $mp.AntivirusSignatureVersion, (Format-Date $mp.AntivirusSignatureLastUpdated))

    # --- Last scan: the newest completed quick or full scan.
    $scans = @(
        if ($mp.QuickScanEndTime) { [pscustomobject]@{ Type = 'Quick'; End = [datetime]$mp.QuickScanEndTime } }
        if ($mp.FullScanEndTime)  { [pscustomobject]@{ Type = 'Full';  End = [datetime]$mp.FullScanEndTime } }
    )
    $lastScan = $scans | Sort-Object End -Descending | Select-Object -First 1

    if ($lastScan) {
        $scanAge = ((Get-Date) - $lastScan.End).TotalDays
        $status = Get-AgeStatus $scanAge $Thresholds.ScanPassMaxDays $Thresholds.ScanWarnMaxDays
        Add-Result $category 'Last scan' $status ('{0} scan finished {1} ({2:N0} days ago)' -f $lastScan.Type, (Format-Date $lastScan.End), $scanAge)
    }
    else {
        Add-Result $category 'Last scan' 'FAIL' 'No completed scan recorded'
    }
}

# ---------------------------------------------------------------------------
# Check 4: Listening TCP ports
# ---------------------------------------------------------------------------
# Lists every TCP socket in the Listen state with the process that owns it.
# Bound to 127.0.0.1 / ::1 (loopback): only reachable from this computer.
# Bound to 0.0.0.0 / :: or a specific IP: reachable from the network, unless the
# firewall blocks it. Well-known risky services reachable that way become a WARN.
function Test-ListeningPorts {
    Write-Section '4. Listening TCP ports'
    $category = 'Network'

    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop
    }
    catch {
        Add-Result $category 'Listening ports' 'WARN' ('Could not list TCP listeners: {0}' -f $_.Exception.Message)
        return
    }

    # Build a PID -> process name lookup once instead of calling Get-Process per port.
    $processNames = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $processNames[$_.Id] = $_.ProcessName }

    $rows = foreach ($l in ($listeners | Sort-Object LocalPort, LocalAddress -Unique)) {
        $address = [string]$l.LocalAddress
        $scope = if ($address -like '127.*' -or $address -eq '::1') { 'Loopback only' }
                 elseif ($address -eq '0.0.0.0' -or $address -eq '::') { 'All interfaces' }
                 else { 'Specific interface' }

        # LocalPort is UInt16; cast to int so the hashtable lookup matches.
        $port = [int]$l.LocalPort
        $note = ''
        if ($scope -ne 'Loopback only' -and $RiskyPorts.ContainsKey($port)) {
            $note = '{0} reachable from the network' -f $RiskyPorts[$port]
        }

        $procId = [int]$l.OwningProcess
        $procName = if ($procId -eq 4) { 'System' }
                    elseif ($processNames.ContainsKey($procId)) { $processNames[$procId] }
                    else { 'unknown' }

        [pscustomobject]@{
            Port    = $port
            Address = $address
            Scope   = $scope
            PID     = $procId
            Process = $procName
            Note    = $note
        }
    }
    $rows = @($rows)

    # Show the full list in the console and keep it for the HTML report.
    $rows | Format-Table Port, Address, Scope, PID, Process, Note -AutoSize | Out-String -Width 200 | Write-Host
    $script:DetailTables['Listening TCP ports'] = $rows

    $exposed = @($rows | Where-Object { $_.Scope -ne 'Loopback only' })
    $risky = @($rows | Where-Object { $_.Note })

    foreach ($r in $risky) {
        Add-Result $category ('Port {0}' -f $r.Port) 'WARN' ('{0} on {1} (process: {2}, PID {3}). Firewall may still block it.' -f $r.Note, $r.Address, $r.Process, $r.PID)
    }

    $summary = '{0} listening socket(s), {1} reachable from the network' -f $rows.Count, $exposed.Count
    if ($risky.Count -gt 0) {
        Add-Result $category 'Listening ports' 'WARN' ('{0}; {1} high-risk service(s) exposed' -f $summary, $risky.Count)
    }
    else {
        Add-Result $category 'Listening ports' 'PASS' ('{0}; no high-risk services exposed' -f $summary)
    }
}

# ---------------------------------------------------------------------------
# Check 5: Startup programs
# ---------------------------------------------------------------------------
# Programs listed here start automatically at logon, which also makes these
# locations a favorite persistence spot for malware. The check lists every
# entry and flags ones that match suspicious patterns or point to missing files.

function Get-CommandPath {
    # Extracts the executable path from a startup command line.
    param([string]$Command)
    $c = [Environment]::ExpandEnvironmentVariables($Command).Trim()
    if ($c -match '^"([^"]+)"') { return $Matches[1] }                        # "C:\path with spaces\app.exe" -args
    if ($c -match '^(.+?\.(exe|com|bat|cmd|vbs|js|ps1))(\s|$)') { return $Matches[1] }  # C:\path\app.exe -args
    return ($c -split '\s+')[0]
}

function Get-StartupNote {
    # Returns a review note for a startup command, or '' if nothing stands out.
    param([string]$Command)
    $notes = @()
    foreach ($pattern in $SuspiciousStartupPatterns.Keys) {
        if ($Command -match $pattern) { $notes += $SuspiciousStartupPatterns[$pattern] }
    }
    # Only check existence for absolute paths; bare names like "rundll32.exe" resolve via PATH.
    $path = Get-CommandPath $Command
    if ($path -and [System.IO.Path]::IsPathRooted($path) -and -not (Test-Path -LiteralPath $path)) {
        $notes += 'target file not found'
    }
    $notes -join '; '
}

function Test-StartupPrograms {
    Write-Section '5. Startup programs'
    $category = 'Startup'

    # Run = every logon; RunOnce = next logon only. WOW6432Node holds 32-bit entries.
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    $entries = New-Object System.Collections.Generic.List[object]

    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }
        try {
            # Get-Item returns a read-only RegistryKey handle; we only read values from it.
            $regKey = Get-Item -Path $key -ErrorAction Stop
            foreach ($name in $regKey.GetValueNames()) {
                $command = [string]$regKey.GetValue($name)
                $entries.Add([pscustomobject]@{
                    Location = $key
                    Name     = if ($name) { $name } else { '(Default)' }
                    Command  = $command
                    Note     = Get-StartupNote $command
                })
            }
        }
        catch {
            Write-Verbose ('Could not read {0}: {1}' -f $key, $_.Exception.Message)
        }
    }

    # Per-user and all-users Startup folders.
    $folders = @(
        [Environment]::GetFolderPath('Startup')
        [Environment]::GetFolderPath('CommonStartup')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    # WScript.Shell.CreateShortcut() on an existing .lnk only READS it;
    # nothing is written unless .Save() is called (it never is here).
    $shell = New-Object -ComObject WScript.Shell

    foreach ($folder in $folders) {
        Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne 'desktop.ini' } |
            ForEach-Object {
                $command = $_.FullName
                if ($_.Extension -eq '.lnk') {
                    $lnk = $shell.CreateShortcut($_.FullName)
                    $command = ('"{0}" {1}' -f $lnk.TargetPath, $lnk.Arguments).Trim()
                }
                $entries.Add([pscustomobject]@{
                    Location = $folder
                    Name     = $_.Name
                    Command  = $command
                    Note     = Get-StartupNote $command
                })
            }
    }

    # Convert the List to a plain array (@($list) throws on generic Lists in PS 5.1).
    $entries = $entries.ToArray()
    if ($entries.Count -gt 0) {
        $entries | Format-Table Name, Command, Note -AutoSize -Wrap | Out-String -Width 200 | Write-Host
        $script:DetailTables['Startup programs'] = $entries
    }

    $flagged = @($entries | Where-Object { $_.Note })
    foreach ($e in $flagged) {
        Add-Result $category $e.Name 'WARN' ('{0} -> {1}' -f $e.Note, $e.Command)
    }

    if ($flagged.Count -gt 0) {
        Add-Result $category 'Startup entries' 'WARN' ('{0} entr(ies) found, {1} flagged for review' -f $entries.Count, $flagged.Count)
    }
    else {
        Add-Result $category 'Startup entries' 'PASS' ('{0} entr(ies) found, none flagged. Review the list for anything you do not recognize.' -f $entries.Count)
    }
}

# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

function ConvertTo-HtmlText {
    # HTML-encodes a value so registry data or process names cannot break the page.
    param($Value)
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-HtmlTableFragment {
    # Builds an HTML table from objects. A "Status" column gets a colored badge.
    param([object[]]$Rows)
    if (-not $Rows -or $Rows.Count -eq 0) { return '<p>No entries.</p>' }

    $columns = $Rows[0].PSObject.Properties.Name
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table><thead><tr>')
    foreach ($c in $columns) { [void]$sb.Append('<th>' + (ConvertTo-HtmlText $c) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $columns) {
            $value = ConvertTo-HtmlText $row.$c
            if ($c -eq 'Status') {
                [void]$sb.Append(('<td><span class="badge {0}">{1}</span></td>' -f $value.ToLower(), $value))
            }
            else {
                [void]$sb.Append('<td>' + $value + '</td>')
            }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    $sb.ToString()
}

function Export-HtmlReport {
    param([string]$Path)

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $osText = if ($os) { '{0} (build {1})' -f $os.Caption, $os.BuildNumber } else { 'unknown' }
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $pass = @($script:Results | Where-Object Status -eq 'PASS').Count
    $warn = @($script:Results | Where-Object Status -eq 'WARN').Count
    $fail = @($script:Results | Where-Object Status -eq 'FAIL').Count

    $details = foreach ($title in $script:DetailTables.Keys) {
        '<h2>{0}</h2>{1}' -f (ConvertTo-HtmlText $title), (ConvertTo-HtmlTableFragment @($script:DetailTables[$title]))
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Check - $(ConvertTo-HtmlText $env:COMPUTERNAME)</title>
<style>
  :root { --bg:#f6f7f9; --fg:#1d2330; --muted:#5b6475; --card:#fff; --line:#dde1e8;
          --pass:#1a7f37; --warn:#9a6700; --fail:#cf222e; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0f1218; --fg:#e6e9ef; --muted:#9aa3b2; --card:#171b23; --line:#2a303b;
            --pass:#3fb950; --warn:#d29922; --fail:#f85149; }
  }
  body { margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
         font:14px/1.5 "Segoe UI", system-ui, sans-serif; }
  main { max-width:1100px; margin:0 auto; }
  h1 { margin:0 0 4px; font-size:24px; }
  h2 { margin:32px 0 8px; font-size:18px; }
  .meta { color:var(--muted); margin-bottom:20px; }
  .tiles { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:8px; }
  .tile { background:var(--card); border:1px solid var(--line); border-radius:8px;
          padding:12px 20px; min-width:110px; }
  .tile b { display:block; font-size:26px; }
  .tile.pass b { color:var(--pass); } .tile.warn b { color:var(--warn); } .tile.fail b { color:var(--fail); }
  .scroll { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; background:var(--card);
          border:1px solid var(--line); border-radius:8px; }
  th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line);
           vertical-align:top; word-break:break-word; }
  th { font-weight:600; color:var(--muted); }
  .badge { display:inline-block; padding:1px 8px; border-radius:10px; font-weight:600;
           color:#fff; font-size:12px; }
  .badge.pass { background:var(--pass); } .badge.warn { background:var(--warn); } .badge.fail { background:var(--fail); }
</style>
</head>
<body>
<main>
<h1>Windows Security Check</h1>
<div class="meta">
  Computer: $(ConvertTo-HtmlText $env:COMPUTERNAME) &middot;
  User: $(ConvertTo-HtmlText "$env:USERDOMAIN\$env:USERNAME") (admin: $isAdmin) &middot;
  OS: $(ConvertTo-HtmlText $osText) &middot;
  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
</div>
<div class="tiles">
  <div class="tile pass"><b>$pass</b>PASS</div>
  <div class="tile warn"><b>$warn</b>WARN</div>
  <div class="tile fail"><b>$fail</b>FAIL</div>
</div>
<h2>Results</h2>
<div class="scroll">$(ConvertTo-HtmlTableFragment $script:Results.ToArray())</div>
$(($details | ForEach-Object { '<div class="scroll">' + $_ + '</div>' }) -join "`n")
</main>
</body>
</html>
"@

    # UTF-8 so non-ASCII program names display correctly.
    [System.IO.File]::WriteAllText($Path, $html, (New-Object System.Text.UTF8Encoding($false)))
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
    Write-Error ('Output folder does not exist: {0}' -f $OutputPath)
    exit 1
}

Write-Host 'Windows Security Check (read-only)' -ForegroundColor Cyan
Write-Host ('Computer: {0}   Started: {1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# Each check handles its own errors, so one failure does not stop the others.
Test-WindowsUpdate
Test-Firewall
Test-Defender
Test-ListeningPorts
Test-StartupPrograms

# Console summary
$pass = @($script:Results | Where-Object Status -eq 'PASS').Count
$warn = @($script:Results | Where-Object Status -eq 'WARN').Count
$fail = @($script:Results | Where-Object Status -eq 'FAIL').Count

Write-Section 'Summary'
Write-Host ('PASS: {0}' -f $pass) -ForegroundColor Green
Write-Host ('WARN: {0}' -f $warn) -ForegroundColor Yellow
Write-Host ('FAIL: {0}' -f $fail) -ForegroundColor Red

$reportPath = Join-Path $OutputPath ('SecurityCheck_{0}_{1}.html' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
try {
    Export-HtmlReport -Path $reportPath
    Write-Host ''
    Write-Host ('HTML report saved to: {0}' -f $reportPath) -ForegroundColor Cyan
}
catch {
    Write-Error ('Could not write the HTML report: {0}' -f $_.Exception.Message)
    exit 1
}
