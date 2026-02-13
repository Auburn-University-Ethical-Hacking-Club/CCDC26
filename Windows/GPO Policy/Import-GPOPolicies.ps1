#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Modular GPO Policy Importer - Automatically imports SEC GPO policies and links them
    to Domain Root, enforced across all machines.

.DESCRIPTION
    Interactive menu-driven script that:
      - Detects your domain automatically
      - Lets you choose which policies to import (all or individual)
      - Imports each GPO from the backup folder structure
      - Links ALL policies to Domain Root with Enforced=Yes
      - Enforced flag prevents child OUs from blocking inheritance

.NOTES
    Must be run as Domain Admin on a Domain Controller or machine with GPMC + RSAT installed.
    Place this script in the same directory as the "gpo_policies" folder.

.POLICIES INCLUDED
    1.  SEC - Account and Password Policy    [Domain root]
    2.  SEC - Audit and Logging Policy       [Domain/OU]
    3.  SEC - Credential Protection          [Domain/OU]
    4.  SEC - PowerShell Hardening           [Domain/OU]
    5.  SEC - Security Options               [Domain/OU]
    6.  SEC - SMB Hardening                  [Domain/OU]
    7.  SEC - USB and Removable Media        [Domain/OU]
    8.  SEC - User Rights Assignment         [Domain/OU]
    9.  SEC - WinRM Hardening                [Domain/OU]
    10. SEC - Windows Defender and ASR       [Domain/OU]
#>

# ============================================================
#  CONFIGURATION
# ============================================================

$ScriptDir     = Split-Path -Parent $MyInvocation.MyCommand.Path
$GPOBackupRoot = $ScriptDir

# Policy definitions: Name, BackupGUID, default link scope, description
$PolicyDefinitions = @(
    [PSCustomObject]@{
        Name        = "SEC - Account and Password Policy"
        GUID        = "A1B2C3D4-0001-0001-0001-000000000001"
        DefaultLink = "Domain"
        Description = "Password length/complexity/expiry, lockout threshold and duration"
        Warning     = "MUST be linked at Domain root to apply to domain accounts."
    },
    [PSCustomObject]@{
        Name        = "SEC - Audit and Logging Policy"
        GUID        = "A1B2C3D4-0002-0002-0002-000000000002"
        DefaultLink = "Domain"
        Description = "Logon, process creation, privilege use, policy change. Security log 1GB."
        Warning     = $null
    },
    [PSCustomObject]@{
        Name        = "SEC - Credential Protection"
        GUID        = "A1B2C3D4-0005-0005-0005-000000000005"
        DefaultLink = "Domain"
        Description = "Disables WDigest plaintext passwords, enables LSA Protection + Credential Guard"
        Warning     = "Credential Guard requires UEFI + Virtualization Based Security."
    },
    [PSCustomObject]@{
        Name        = "SEC - PowerShell Hardening"
        GUID        = "A1B2C3D4-0007-0007-0007-000000000007"
        DefaultLink = "Domain"
        Description = "RemoteSigned execution policy, Script Block Logging, Module Logging, Transcription"
        Warning     = $null
    },
    [PSCustomObject]@{
        Name        = "SEC - Security Options"
        GUID        = "A1B2C3D4-0004-0004-0004-000000000004"
        DefaultLink = "Domain"
        Description = "NTLMv2 only, hide last username, CTRL+ALT+DEL, UAC Admin Approval, no anonymous SAM"
        Warning     = $null
    },
    [PSCustomObject]@{
        Name        = "SEC - SMB Hardening"
        GUID        = "A1B2C3D4-0012-0012-0012-000000000012"
        DefaultLink = "Domain"
        Description = "Disables SMBv1, requires SMB signing, enables SMB encryption, restricts NTLM over SMB"
        Warning     = "SMB encryption requires all clients to support SMBv3. Test before deploying domain-wide."
    },
    [PSCustomObject]@{
        Name        = "SEC - USB and Removable Media"
        GUID        = "A1B2C3D4-0010-0010-0010-000000000010"
        DefaultLink = "Domain"
        Description = "Disables autorun/autoplay, blocks write and execute on all removable storage"
        Warning     = $null
    },
    [PSCustomObject]@{
        Name        = "SEC - User Rights Assignment"
        GUID        = "A1B2C3D4-0003-0003-0003-000000000003"
        DefaultLink = "Domain"
        Description = "Restricts local/network/RDP logon rights, removes dangerous OS-level privileges"
        Warning     = $null
    },
    [PSCustomObject]@{
        Name        = "SEC - WinRM Hardening"
        GUID        = "A1B2C3D4-0013-0013-0013-000000000013"
        DefaultLink = "Domain"
        Description = "Disables unencrypted WinRM, Basic/Digest/CredSSP auth, disables WinRM service auto-start"
        Warning     = "WinRM service is set to disabled. Re-enable manually on machines that need remote management."
    },
    [PSCustomObject]@{
        Name        = "SEC - Windows Defender and ASR"
        GUID        = "A1B2C3D4-0006-0006-0006-000000000006"
        DefaultLink = "Domain"
        Description = "Real-time protection, cloud protection, 9 ASR rules in Block mode"
        Warning     = "ASR rules may block legitimate apps. Consider Audit mode (2) first in production."
    }
)

# ============================================================
#  HELPER FUNCTIONS
# ============================================================

function Write-Header {
    Clear-Host
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "   MODULAR GPO POLICY IMPORTER" -ForegroundColor Cyan
    Write-Host "   Windows Domain Hardening - Automated Import and Linking" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $color = switch ($Type) {
        "INFO"    { "White" }
        "OK"      { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SECTION" { "Cyan" }
    }
    $prefix = switch ($Type) {
        "INFO"    { "  [*]" }
        "OK"      { "  [+]" }
        "WARN"    { "  [!]" }
        "ERROR"   { "  [X]" }
        "SECTION" { "`n  ---" }
    }
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Test-Prerequisites {
    Write-Status "Checking prerequisites..." "SECTION"

    $allGood = $true

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Status "GroupPolicy module not found." "ERROR"
        Write-Status "Fix: Install-WindowsFeature -Name GPMC" "WARN"
        $allGood = $false
    } else {
        Write-Status "GroupPolicy module found" "OK"
    }

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Status "ActiveDirectory module not found." "ERROR"
        Write-Status "Fix: Install-WindowsFeature -Name RSAT-AD-PowerShell" "WARN"
        $allGood = $false
    } else {
        Write-Status "ActiveDirectory module found" "OK"
    }

    if (-not (Test-Path $GPOBackupRoot)) {
        Write-Status "GPO backup root not found: $GPOBackupRoot" "ERROR"
        $allGood = $false
    } else {
        Write-Status "GPO backup root found: $GPOBackupRoot" "OK"
    }

    # Verify each policy folder exists
    $missingFolders = @()
    foreach ($policy in $PolicyDefinitions) {
        $folder = Join-Path $GPOBackupRoot $policy.Name
        if (-not (Test-Path $folder)) {
            $missingFolders += $policy.Name
        }
    }
    if ($missingFolders.Count -gt 0) {
        Write-Status "Missing policy backup folders:" "WARN"
        foreach ($m in $missingFolders) { Write-Host "      - $m" -ForegroundColor Yellow }
    } else {
        Write-Status "All $($PolicyDefinitions.Count) policy backup folders found" "OK"
    }

    if ($allGood) {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    }

    return $allGood
}

function Get-DomainInfo {
    try {
        $domain = Get-ADDomain
        return $domain
    } catch {
        Write-Status "Could not retrieve domain info. Are you on a domain-joined machine as Domain Admin?" "ERROR"
        return $null
    }
}



function Show-PolicyMenu {
    param([array]$Policies)

    Write-Host "  Domain-level policies (default link: Domain Root):" -ForegroundColor DarkGray
    Write-Host ""

    $index = 1
    foreach ($policy in $Policies) {
        Write-Host ("  [{0,2}]  {1}" -f $index, $policy.Name) -ForegroundColor White
        Write-Host ("        {0}" -f $policy.Description) -ForegroundColor DarkGray
        if ($policy.Warning) {
            Write-Host ("        ! {0}" -f $policy.Warning) -ForegroundColor Yellow
        }
        Write-Host ""
        $index++
    }

    Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "   [A]  Import ALL policies" -ForegroundColor Green
    Write-Host "   [Q]  Quit" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Enter numbers separated by commas to import specific policies" -ForegroundColor DarkGray
    Write-Host "  Example: 1,4,6  imports Account/Password, PowerShell, SMB" -ForegroundColor DarkGray
    Write-Host ""

    return (Read-Host "  Your selection")
}

function Import-GPOFromBackup {
    param(
        [PSCustomObject]$Policy,
        [string]$DomainName
    )

    $backupFolder = Join-Path $GPOBackupRoot $Policy.Name

    if (-not (Test-Path $backupFolder)) {
        Write-Status "Backup folder missing: $backupFolder" "ERROR"
        return $false
    }

    $existing = Get-GPO -Name $Policy.Name -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Status "GPO '$($Policy.Name)' already exists — skipping import, will re-link" "WARN"
        return $true
    }

    try {
        Write-Status "Creating GPO: $($Policy.Name)" "INFO"
        New-GPO -Name $Policy.Name -Domain $DomainName -ErrorAction Stop | Out-Null

        Write-Status "Importing settings from backup..." "INFO"
        Import-GPO -BackupGpoName $Policy.Name `
                   -TargetName    $Policy.Name `
                   -Path          $backupFolder `
                   -Domain        $DomainName `
                   -ErrorAction   Stop | Out-Null

        Write-Status "Import complete" "OK"
        return $true
    } catch {
        Write-Status "Import failed: $_" "ERROR"
        return $false
    }
}

function Link-GPOToTarget {
    param(
        [PSCustomObject]$Policy,
        [string]$TargetDN,
        [string]$DomainName
    )

    try {
        $existingLinks = (Get-GPInheritance -Target $TargetDN -Domain $DomainName).GpoLinks |
                         Where-Object { $_.DisplayName -eq $Policy.Name }

        if ($existingLinks) {
            # Link exists — ensure it is Enforced and Enabled
            Write-Status "Link already exists — ensuring Enforced=Yes and Enabled=Yes" "WARN"
            Set-GPLink -Name        $Policy.Name `
                       -Target      $TargetDN `
                       -Domain      $DomainName `
                       -Enforced    Yes `
                       -LinkEnabled Yes `
                       -ErrorAction Stop | Out-Null
            Write-Status "Link updated: Enforced=Yes" "OK"
            return $true
        }

        # Create new link with Enforced=Yes so child OUs cannot block it
        New-GPLink -Name        $Policy.Name `
                   -Target      $TargetDN `
                   -Domain      $DomainName `
                   -LinkEnabled Yes `
                   -Enforced    Yes `
                   -ErrorAction Stop | Out-Null

        Write-Status "Linked to $TargetDN  [Enforced=Yes — applies to ALL machines]" "OK"
        return $true
    } catch {
        Write-Status "Linking failed: $_" "ERROR"
        return $false
    }
}

function Invoke-PolicyImport {
    param(
        [array]$PoliciesToImport,
        [string]$DomainName,
        [string]$DomainDN
    )

    $results = @()

    foreach ($policy in $PoliciesToImport) {
        Write-Host ""
        Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Processing: $($policy.Name)" -ForegroundColor Cyan
        Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray

        if ($policy.Warning) {
            Write-Status $policy.Warning "WARN"
        }

        # Always link to domain root — enforced across all machines
        $linkTarget = $DomainDN
        Write-Status "Link target: Domain Root ($DomainName) [Enforced]" "INFO"

        # Import GPO
        $imported = Import-GPOFromBackup -Policy $policy -DomainName $DomainName
        if (-not $imported) {
            $results += [PSCustomObject]@{ Name = $policy.Name; Status = "Failed"; LinkedTo = "N/A" }
            continue
        }

        # Link GPO with Enforced=Yes
        $linked = Link-GPOToTarget -Policy $policy -TargetDN $linkTarget -DomainName $DomainName
        if ($linked) {
            $results += [PSCustomObject]@{ Name = $policy.Name; Status = "Success"; LinkedTo = $linkTarget }
        } else {
            $results += [PSCustomObject]@{ Name = $policy.Name; Status = "Failed"; LinkedTo = $linkTarget }
        }
    }

    return $results
}

function Show-Summary {
    param([array]$Results)

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "   IMPORT SUMMARY" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""

    foreach ($r in $Results) {
        $color = switch ($r.Status) {
            "Success" { "Green"  }
            "Failed"  { "Red"    }
            "Skipped" { "Yellow" }
        }
        Write-Host ("  [{0,-7}]  {1}" -f $r.Status, $r.Name) -ForegroundColor $color
        if ($r.LinkedTo -ne "N/A") {
            Write-Host ("             -> {0}" -f $r.LinkedTo) -ForegroundColor DarkGray
        }
    }

    $success = ($Results | Where-Object Status -eq "Success").Count
    $failed  = ($Results | Where-Object Status -eq "Failed").Count
    $skipped = ($Results | Where-Object Status -eq "Skipped").Count

    Write-Host ""
    Write-Host ("  Total: {0}  |  Success: {1}  |  Failed: {2}  |  Skipped: {3}" -f
        $Results.Count, $success, $failed, $skipped) -ForegroundColor Cyan
    Write-Host ""

    if ($failed -eq 0 -and $success -gt 0) {
        Write-Host "  All selected policies imported and enforced at Domain Root!" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Policies are set to Enforced=Yes — they apply to ALL machines" -ForegroundColor Green
        Write-Host "  in the domain and cannot be blocked by child OU admins." -ForegroundColor Green
        Write-Host ""
        Write-Host "  Recommended next steps:" -ForegroundColor Cyan
        Write-Host "    1. Run on any target machine:  gpupdate /force" -ForegroundColor White
        Write-Host "    2. Verify applied policies:    gpresult /h C:\gp_report.html" -ForegroundColor White
        Write-Host "    3. Open C:\gp_report.html to review effective settings" -ForegroundColor White
        Write-Host "    4. Check Event Viewer > Windows Logs > System for any GPO errors" -ForegroundColor White
    } elseif ($failed -gt 0) {
        Write-Host "  $failed polic$(if($failed -eq 1){'y'}else{'ies'}) failed to import." -ForegroundColor Yellow
        Write-Host "  Ensure you are running as Domain Admin and all backup folders are present." -ForegroundColor Yellow
    }
    Write-Host ""
}

# ============================================================
#  MAIN
# ============================================================

Write-Header

if (-not (Test-Prerequisites)) {
    Write-Host ""
    Read-Host "  Prerequisites not met. Press Enter to exit"
    exit 1
}

Write-Status "Detecting domain..." "SECTION"
$domain = Get-DomainInfo
if (-not $domain) {
    Read-Host "  Press Enter to exit"
    exit 1
}

$domainName = $domain.DNSRoot
$domainDN   = $domain.DistinguishedName
Write-Status "Domain:     $domainName" "OK"
Write-Status "Domain DN:  $domainDN" "OK"
Write-Status "All policies will be linked here with Enforced=Yes" "OK"

# Show menu
Write-Header
Write-Host "  Domain: $domainName" -ForegroundColor Green
Write-Host "  Backup: $GPOBackupRoot" -ForegroundColor DarkGray
Write-Host ""

$menuChoice = Show-PolicyMenu -Policies $PolicyDefinitions

if ($menuChoice.ToUpper() -eq "Q") {
    Write-Host "`n  Exiting.`n" -ForegroundColor Yellow
    exit 0
}

# Resolve selection
$selectedPolicies = @()

if ($menuChoice.ToUpper() -eq "A") {
    $selectedPolicies = $PolicyDefinitions
    Write-Status "All $($PolicyDefinitions.Count) policies selected" "OK"
} else {
    foreach ($num in ($menuChoice -split "," | ForEach-Object { $_.Trim() })) {
        if ($num -match "^\d+$") {
            $idx = [int]$num - 1
            if ($idx -ge 0 -and $idx -lt $PolicyDefinitions.Count) {
                $selectedPolicies += $PolicyDefinitions[$idx]
            } else {
                Write-Status "Number $num is out of range — ignored" "WARN"
            }
        } else {
            Write-Status "Invalid entry '$num' — ignored" "WARN"
        }
    }
}

if ($selectedPolicies.Count -eq 0) {
    Write-Status "No valid policies selected. Exiting." "ERROR"
    Read-Host "  Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "  $($selectedPolicies.Count) polic$(if($selectedPolicies.Count -eq 1){'y'}else{'ies'}) queued for import:" -ForegroundColor Cyan
foreach ($p in $selectedPolicies) {
    Write-Host "    - $($p.Name)" -ForegroundColor White
}
Write-Host ""
$confirm = Read-Host "  Proceed? (Y/N)"
if ($confirm.ToUpper() -ne "Y") {
    Write-Host "`n  Cancelled.`n" -ForegroundColor Yellow
    exit 0
}

# Run import — all policies linked to domain root with Enforced=Yes
$results = Invoke-PolicyImport `
    -PoliciesToImport $selectedPolicies `
    -DomainName       $domainName `
    -DomainDN         $domainDN

Show-Summary -Results $results
Read-Host "  Press Enter to exit"
