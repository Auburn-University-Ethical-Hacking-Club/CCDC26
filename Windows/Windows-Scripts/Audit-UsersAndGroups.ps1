<#
.SYNOPSIS
  Monitor local group membership (Admins), detect additions/removals, and surface privilege elevation events.

.DESCRIPTION
  - Stores previous snapshot of local Administrators group in a JSON file.
  - Scans Windows Security log for EventIDs related to group changes and privileged actions:
      4728-4738 (group membership changes range), 4672 (special privileges assigned),
      4673 (privileged service called), 4624 (logon) and flags elevated token types.
  - Produces JSON lines log and optional webhook/email alerting.

.NOTES
  Run with elevated privileges to read Security log and query local groups.
#>

param(
  [string]$SnapshotPath = "C:\Scripts\admin_snapshot.json",
  [string]$OutLog = "C:\Scripts\Audit-UsersAndGroups.log",
  [int]$LookbackMinutes = 15,
  [string]$WebhookUrl = "",            # optional: POST JSON alert to webhook
  [switch]$SendEmail,                 # optional: send email for critical alerts (configure inside)
  [switch]$VerboseLogging
)

function Write-JsonLog {
    param($obj)
    $json = $obj | ConvertTo-Json -Depth 6
    $ts = (Get-Date).ToString("o")
    "$ts $json" | Out-File -FilePath $OutLog -Append -Encoding utf8
    if ($WebhookUrl -and $obj.Severity -eq "High") {
        try {
            Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $json -ContentType 'application/json' -ErrorAction Stop
        } catch {
            if ($VerboseLogging) { "Webhook failed: $_" | Out-File -FilePath $OutLog -Append }
        }
    }
}

function Get-LocalAdmins {
    # Use Get-LocalGroupMember if available (PowerShell 5.1+ on modern Windows). Fallback to net localgroup.
    try {
        $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | ForEach-Object {
            @{ Name = $_.Name; ObjectClass = $_.ObjectClass; Sid = $_.SID.Value }
        }
    } catch {
        # fallback parse net localgroup
        $text = net localgroup Administrators 2>$null
        $members = @()
        if ($text) {
            $lines = ($text -split "`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch "^(Alias|Members|The command completed|^-+)$" }
            foreach ($l in $lines) {
                $members += @{ Name = $l; ObjectClass = "Unknown"; Sid = "" }
            }
        }
    }
    return $members
}

function Load-Snapshot {
    param($path)
    if (Test-Path $path) {
        try { return Get-Content $path -Raw | ConvertFrom-Json } catch { return @() }
    }
    return @()
}

function Save-Snapshot {
    param($members, $path)
    $members | ConvertTo-Json -Depth 4 | Set-Content -Path $path -Encoding utf8
}

# ---------- Main ----------
if (-not (Test-Path (Split-Path $SnapshotPath))) { New-Item -Path (Split-Path $SnapshotPath) -ItemType Directory -Force | Out-Null }
if (-not (Test-Path (Split-Path $OutLog))) { New-Item -Path (Split-Path $OutLog) -ItemType Directory -Force | Out-Null }

$prev = Load-Snapshot -path $SnapshotPath
$current = Get-LocalAdmins

# compare
$prevNames = @($prev | ForEach-Object { $_.Name })
$curNames = @($current | ForEach-Object { $_.Name })

$added = $curNames | Where-Object { $_ -notin $prevNames }
$removed = $prevNames | Where-Object { $_ -notin $curNames }

if ($added.Count -gt 0 -or $removed.Count -gt 0) {
    $alert = [PSCustomObject]@{
        Source = "LocalGroupSnapshot"
        Severity = "High"
        Host = $env:COMPUTERNAME
        Added = $added
        Removed = $removed
        PrevCount = $prevNames.Count
        CurCount = $curNames.Count
        Time = (Get-Date).ToString("o")
    }
    Write-JsonLog $alert
}

# Save new snapshot for next run
Save-Snapshot -members $current -path $SnapshotPath

# ------------- Security Log scan -------------
$since = (Get-Date).AddMinutes(-1 * [int]$LookbackMinutes)

# Event IDs to monitor (based on your spec)
$eventIDs = @(4728,4729,4732,4733,4738,4672,4673,4624)

# Use Get-WinEvent for performance and structured data
$filter = @{
    LogName = 'Security'
    StartTime = $since
    Id = $eventIDs
}

try {
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
} catch {
    $events = @()
    "$((Get-Date).ToString('o')) ERROR reading Security log: $_" | Out-File -FilePath $OutLog -Append
}

foreach ($e in $events) {
    $record = @{
        Source = "SecurityEvent"
        Severity = "Medium"
        Host = $env:COMPUTERNAME
        EventId = $e.Id
        TimeCreated = $e.TimeCreated.ToString("o")
        Message = ($e.Message -replace "`r`n"," ")
    }

    # Enrich with basic parsing where useful
    try {
        # Many events include "Subject: Security ID: ... Account Name: ..." - parse Account Name/Target Name heuristically
        # This is conservative parsing — you may tune for your environment.
        if ($e.Properties) {
            $propVals = $e.Properties | ForEach-Object { $_.Value }
            $record.Properties = $propVals
        }
        # Mark high severity for admin group membership changes or privileged assignments
        if ($e.Id -in @(4728,4729,4732,4733,4738)) { $record.Severity = "High" }
        if ($e.Id -eq 4672) { $record.Severity = "High"; $record.Note = "Special privileges assigned (possible elevation)" }
        if ($e.Id -eq 4624) {
            # Event 4624 details: Authentication Package, Logon Type, Elevated token?
            if ($e.Message -match "Logon Type:\s+(\d+)") {
                $logonType = [int]$matches[1]
                $record.LogonType = $logonType
                # interactive (2), remote interactive (10) or service(5) etc. Consider remote interactive as higher risk for lateral movement
                if ($logonType -in 10,3) { $record.Severity = "Medium" }
            }
            # look for Elevated Token (if present in message)
            if ($e.Message -match "Elevated Token:\s+(Yes|No)") {
                $record.ElevatedToken = $matches[1]
                if ($matches[1] -eq "Yes") { $record.Severity = "High" }
            }
        }
    } catch { }

    Write-JsonLog $record
}

# Optional: small housekeeping
# Keep log size limited: rotate if larger than X MB (simple)
$maxMB = 50
try {
    $sizeMB = (Get-Item $OutLog).Length / 1MB
    if ($sizeMB -gt $maxMB) {
        $bak = $OutLog + "." + (Get-Date -Format "yyyyMMddHHmmss") + ".bak"
        Move-Item -Path $OutLog -Destination $bak -Force
        "" | Out-File -FilePath $OutLog
    }
} catch {}

if ($VerboseLogging) { "Audit run complete." }
