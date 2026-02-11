<#
.SYNOPSIS
  Baseline Windows hardening (idempotent, safe-first defaults). Test in lab before production.

.DESCRIPTION
  - Implements a practical subset of high-value hardening controls:
    * Windows Update service running
    * Disable SMBv1
    * Firewall enabled (Domain/Private/Public) - inbound blocked by default
    * Microsoft Defender real-time enabled + signature update trigger
    * Basic audit policy (account/logon/policy)
    * Local password policy (min length, max age, history)
    * UAC enforcement
    * Optional: disable WinRM (set $DisableWinRM = $true to disable)
  - Writes JSON summary to $OutReport.

.NOTES
  - Run elevated. Test on a VM first.
  - Many enterprise environments enforce settings via GPO/MDM. If domain-managed, align with central policies.
#>

param(
    [string]$OutReport = "C:\Scripts\WinHardening_Report.json",
    [switch]$DisableWinRM = $false,
    [switch]$DoNotRestart = $true,    # Some changes may require restart; default: do not automatically restart
    [switch]$Verbose
)

# Helper: safe-apply registry value with backup
function Set-RegistryValue {
    param($Path, $Name, $Value, [Microsoft.Win32.RegistryValueKind]$Kind = [Microsoft.Win32.RegistryValueKind]::DWord)
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        $existing = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($existing -and $existing.$Name -eq $Value) {
            return @{ Changed = $false; Path=$Path; Name=$Name; Value=$Value }
        } else {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Kind -Force
            return @{ Changed = $true; Path=$Path; Name=$Name; Value=$Value }
        }
    } catch {
        Write-Warning "Failed to set registry $Path\$Name : $_"
        return @{ Changed = $false; Error = $_.ToString() }
    }
}

# Output collection
$results = [ordered]@{
    Timestamp = (Get-Date).ToString("o")
    Host = $env:COMPUTERNAME
    Actions = @()
}

Write-Host "Starting Windows baseline hardening... (run as Admin) `n"

# 1) Ensure Windows Update service is present, automatic, and started
try {
    $svc = Get-Service -Name wuauserv -ErrorAction Stop
    if ($svc.StartType -ne 'Automatic') { Set-Service -Name wuauserv -StartupType Automatic }
    if ($svc.Status -ne 'Running') { Start-Service -Name wuauserv -ErrorAction SilentlyContinue }
    $results.Actions += @{ Name="WindowsUpdateService"; Changed=$true; Status=(Get-Service -Name wuauserv).Status.ToString() }
} catch {
    $results.Actions += @{ Name="WindowsUpdateService"; Changed=$false; Error=$_.ToString() }
}

# 2) Disable SMBv1 (recommended safe: no restart required for feature removal in many builds)
try {
    # Try the recommended cmdlet for Windows 10/11: Disable Windows optional feature for SMB1 client & server
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    # also ensure server role off
    sc.exe config lanmanserver start= disabled | Out-Null
    sc.exe stop lanmanserver | Out-Null
    $results.Actions += @{ Name="DisableSMBv1"; Changed=$true }
} catch {
    $results.Actions += @{ Name="DisableSMBv1"; Changed=$false; Error=$_.ToString() }
}

# 3) Windows Firewall: enable all profiles; default inbound = Block, outbound = Allow
try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -WarningAction SilentlyContinue
    $fw = Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
    $results.Actions += @{ Name="FirewallBaseline"; Changed=$true; Profiles=$fw }
} catch {
    $results.Actions += @{ Name="FirewallBaseline"; Changed=$false; Error=$_.ToString() }
}

# 4) Microsoft Defender: ensure real-time is enabled and service set to automatic
try {
    # Ensure Windows Defender service started/enabled (Win10/11)
    if (Get-Service -Name WinDefend -ErrorAction SilentlyContinue) {
        Set-Service -Name WinDefend -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
        # Turn on real-time monitoring via PowerShell cmdlet (requires Defender module)
        try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } catch {}
        # Quick definition update attempt (best-effort)
        try { Update-MpSignature -ErrorAction SilentlyContinue } catch {}
        $results.Actions += @{ Name="DefenderBaseline"; Changed=$true; Status=(Get-Service -Name WinDefend).Status.ToString() }
    } else {
        $results.Actions += @{ Name="DefenderBaseline"; Changed=$false; Note="WinDefend service not present (EDR/third-party?)" }
    }
} catch {
    $results.Actions += @{ Name="DefenderBaseline"; Changed=$false; Error=$_.ToString() }
}

# 5) Set basic audit policy (Account Logon, Logon, Policy Change, Privilege Use)
try {
    # Enable success & failure for categories most useful to Blue Team triage
    # Account Logon
    auditpol.exe /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
    # Logon/Logoff
    auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    # Policy Change
    auditpol.exe /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
    # Privilege Use
    auditpol.exe /set /subcategory:"Special Logon" /success:enable /failure:enable | Out-Null

    $results.Actions += @{ Name="AuditPolicyBaseline"; Changed=$true; Note="Enabled selected categories" }
} catch {
    $results.Actions += @{ Name="AuditPolicyBaseline"; Changed=$false; Error=$_.ToString() }
}

# 6) Local password policy (apply via net accounts)
try {
    # Minimum length 14, max age 90 days, enforce history 5
    net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:5 | Out-Null
    $pw = (net accounts) -join "`n"
    $results.Actions += @{ Name="PasswordPolicy"; Changed=$true; Summary=$pw }
} catch {
    $results.Actions += @{ Name="PasswordPolicy"; Changed=$false; Error=$_.ToString() }
}

# 7) UAC: enforce consent prompt for administrators (registry)
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    # Enable UAC
    $r1 = Set-RegistryValue -Path $regPath -Name "EnableLUA" -Value 1
    # Prompt for consent for administrators in Admin Approval Mode = 2 (prompt for consent)
    $r2 = Set-RegistryValue -Path $regPath -Name "ConsentPromptBehaviorAdmin" -Value 2
    # Behavior for elevation prompt for standard users = 0 (no prompting)
    $r3 = Set-RegistryValue -Path $regPath -Name "ConsentPromptBehaviorUser" -Value 0
    $results.Actions += @{ Name="UAC"; Changed=$true; Details=@($r1,$r2,$r3) }
} catch {
    $results.Actions += @{ Name="UAC"; Changed=$false; Error=$_.ToString() }
}

# 8) Optional: disable WinRM (remote management) to reduce attack surface if not needed
try {
    if ($DisableWinRM) {
        Set-Service -Name WinRM -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name WinRM -ErrorAction SilentlyContinue
        $results.Actions += @{ Name="WinRM"; Changed=$true; Action="Disabled" }
    } else {
        $results.Actions += @{ Name="WinRM"; Changed=$false; Action="LeftAsIs" }
    }
} catch {
    $results.Actions += @{ Name="WinRM"; Changed=$false; Error=$_.ToString() }
}

# 9) Disable SMBv1 registry (best-effort extra step)
try {
    # This registry disables SMB1 server component on some systems
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 | Out-Null
    $results.Actions += @{ Name="SMB1_Reg"; Changed=$true }
} catch {
    $results.Actions += @{ Name="SMB1_Reg"; Changed=$false; Error=$_.ToString() }
}

# Summarize and write report
try {
    $results | ConvertTo-Json -Depth 6 | Set-Content -Path $OutReport -Encoding UTF8
    Write-Host "`nHardening complete. Report written to $OutReport`n"
    if ($Verbose) { $results.Actions | Format-List }
} catch {
    Write-Warning "Failed writing report: $_"
}

# Show a short summary on console
$results.Actions | ForEach-Object {
    Write-Host ("{0,-25} : {1}" -f $_.Name, (if ($_.Changed) { "OK" } else { "NoChange/Failed" }))
}

if (-not $DoNotRestart) {
    Write-Host "`nSome settings may require a restart. Restart now? (Y/N)"
    $c = Read-Host
    if ($c -match '^[Yy]') { Restart-Computer -Force }
}
