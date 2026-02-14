# CCDC Rapid Hardening Script
# Combines best practices from multiple sources including USF CH-DC team
# Designed for fast deployment in CCDC competitions
#
# Usage:
#   .\CCDC-Rapid-Harden.ps1                    # Interactive mode
#   .\CCDC-Rapid-Harden.ps1 -Quick             # Run all safe hardenings
#   .\CCDC-Rapid-Harden.ps1 -Aggressive        # Maximum hardening (may break things)
#   .\CCDC-Rapid-Harden.ps1 -ChangePasswords   # Also change all user passwords
#
#Requires -RunAsAdministrator

param(
    [switch]$Quick,
    [switch]$Aggressive,
    [switch]$ChangePasswords,
    [switch]$NoBackup,
    [string]$NewPassword = ""
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "C:\CCDC_Hardening_$timestamp.txt"
$errorLog = "$env:USERPROFILE\Desktop\hardening_errors_$timestamp.txt"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logMessage = "[$(Get-Date -Format 'HH:mm:ss')] [$Level] $Message"
    Write-Host $logMessage -ForegroundColor $(if($Level -eq "ERROR"){"Red"}elseif($Level -eq"SUCCESS"){"Green"}elseif($Level -eq"WARN"){"Yellow"}else{"White"})
    Add-Content -Path $logFile -Value $logMessage
}

Write-Host @"
╔═══════════════════════════════════════════════════════════════╗
║                                                                 ║
║           CCDC RAPID HARDENING SCRIPT                          ║
║           Battle-Tested & Competition-Ready                    ║
║                                                                 ║
╚═══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "CCDC Hardening Script Started" "INFO"
Write-Log "Computer: $env:COMPUTERNAME" "INFO"
Write-Log "Domain: $env:USERDNSDOMAIN" "INFO"

# Detect environment
$isDC = (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") -ne $null
$hasIIS = (Get-Service -Name W3SVC -ErrorAction SilentlyContinue) -ne $null
$hasSQL = (Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue).Count -gt 0

Write-Log "Environment Detection:" "INFO"
Write-Log "  Domain Controller: $isDC"
Write-Log "  IIS Installed: $hasIIS"
Write-Log "  SQL Server: $hasSQL"

if ($isDC) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
}

# =============================================================================
# CREDENTIAL PROTECTION (CRITICAL - Prevents Mimikatz and PTH attacks)
# =============================================================================
function Enable-CredentialProtection {
    Write-Log "=== CREDENTIAL PROTECTION ===" "INFO"
    
    # Disable storage of LM hash
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f | Out-Null
    
    # Force NTLMv2 only
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
    
    # Disable WDigest plaintext password storage (CRITICAL - stops cleartext passwords in memory)
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
    Write-Log "Disabled WDigest credential caching (prevents cleartext passwords in memory)" "SUCCESS"
    
    # Enable LSASS protection (RunAsPPL) - Prevents Mimikatz
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
    Write-Log "Enabled LSASS protection (RunAsPPL - prevents Mimikatz)" "SUCCESS"
    
    # Enable LSASS auditing
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null
    
    # Disable anonymous SAM enumeration
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f | Out-Null
    
    # Prevent NTLM null session fallback
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f | Out-Null
    
    # Require LDAP signing
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f | Out-Null
    
    if ($isDC) {
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f | Out-Null
    }
    
    # Disable PKU2U
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" /v AllowOnlineID /t REG_DWORD /d 0 /f | Out-Null
    
    Write-Log "Credential protection enabled" "SUCCESS"
}

# =============================================================================
# WINDOWS DEFENDER HARDENING
# =============================================================================
function Enable-DefenderHardening {
    Write-Log "=== WINDOWS DEFENDER HARDENING ===" "INFO"
    
    # Start Windows Defender service
    Start-Service WinDefend -ErrorAction SilentlyContinue
    
    # Enable Defender
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v ServiceKeepAlive /t REG_DWORD /d 1 /f | Out-Null
    
    # Real-time protection
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableIOAVProtection /t REG_DWORD /d 0 /f | Out-Null
    
    # Cloud protection - MAXIMUM
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 3 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v MpCloudBlockLevel /t REG_DWORD /d 6 /f | Out-Null
    
    # Scanning
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v CheckForSignaturesBeforeRunningScan /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v DisableHeuristics /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v DisableArchiveScanning /t REG_DWORD /d 0 /f | Out-Null
    
    # Tamper Protection
    reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 5 /f | Out-Null
    Write-Log "Enabled Tamper Protection" "SUCCESS"
    
    # CRITICAL: Remove ALL Defender exclusions (Red team loves to add these)
    Write-Log "Removing ALL Defender exclusions..." "WARN"
    try {
        ForEach ($ExcludedExt in (Get-MpPreference).ExclusionExtension) {
            Remove-MpPreference -ExclusionExtension $ExcludedExt -ErrorAction SilentlyContinue | Out-Null
        }
        ForEach ($ExcludedIp in (Get-MpPreference).ExclusionIpAddress) {
            Remove-MpPreference -ExclusionIpAddress $ExcludedIp -ErrorAction SilentlyContinue | Out-Null
        }
        ForEach ($ExcludedDir in (Get-MpPreference).ExclusionPath) {
            Remove-MpPreference -ExclusionPath $ExcludedDir -ErrorAction SilentlyContinue | Out-Null
        }
        ForEach ($ExcludedProc in (Get-MpPreference).ExclusionProcess) {
            Remove-MpPreference -ExclusionProcess $ExcludedProc -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Log "Removed all Defender exclusions" "SUCCESS"
    } catch {
        Write-Log "Error removing exclusions: $_" "WARN"
    }
    
    # Attack Surface Reduction Rules (ASR)
    Write-Log "Enabling Attack Surface Reduction rules..."
    try {
        # Block Office from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block Office from creating executable content
        Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block Office from injecting into processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block JavaScript/VBScript from launching downloaded content
        Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block obfuscated scripts
        Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block executable content from email
        Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block Win32 API calls from Office macros
        Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block PSExec and WMI commands
        Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block untrusted USB processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Use advanced ransomware protection
        Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block executable files from running unless criteria met
        Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block credential stealing from lsass.exe
        Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block Office communication apps from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block Adobe Reader from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        # Block WMI persistence
        Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue | Out-Null
        
        # Remove ASR exclusions
        ForEach ($ExcludedASR in (Get-MpPreference).AttackSurfaceReductionOnlyExclusions) {
            Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ExcludedASR -ErrorAction SilentlyContinue | Out-Null
        }
        
        Write-Log "Attack Surface Reduction rules enabled" "SUCCESS"
    } catch {
        Write-Log "ASR rules not supported on this OS version" "WARN"
    }
    
    Write-Log "Windows Defender hardening complete" "SUCCESS"
}

# =============================================================================
# CVE-SPECIFIC MITIGATIONS
# =============================================================================
function Enable-CVEMitigations {
    Write-Log "=== CVE MITIGATIONS ===" "INFO"
    
    # CVE-2021-34527 (PrintNightmare)
    Write-Log "Mitigating PrintNightmare (CVE-2021-34527)..."
    reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f | Out-Null
    reg delete "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /f 2>$null
    reg delete "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v UpdatePromptSettings /f 2>$null
    reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f | Out-Null
    
    # Disable Print Spooler (if not needed)
    if ($Aggressive) {
        net stop spooler 2>$null | Out-Null
        sc.exe config spooler start=disabled | Out-Null
        Write-Log "Disabled Print Spooler service" "SUCCESS"
    }
    
    if ($isDC) {
        # CVE-2020-1472 (Zerologon)
        Write-Log "Mitigating Zerologon (CVE-2020-1472)..."
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "vulnerablechannelallowlist" -Force -ErrorAction SilentlyContinue | Out-Null
        
        # CVE-2021-42278 & CVE-2021-42287 (noPac)
        Write-Log "Mitigating noPac (CVE-2021-42278/42287)..."
        try {
            Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota"="0"} -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Set Machine Account Quota to 0" "SUCCESS"
        } catch {
            Write-Log "Could not set Machine Account Quota (may not have permissions)" "WARN"
        }
    }
    
    Write-Log "CVE mitigations applied" "SUCCESS"
}

# =============================================================================
# NETWORK SECURITY
# =============================================================================
function Enable-NetworkSecurity {
    Write-Log "=== NETWORK SECURITY ===" "INFO"
    
    # Disable SMBv1 (prevents WannaCry-style attacks)
    Write-Log "Disabling SMBv1..."
    sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi | Out-Null
    sc.exe config mrxsmb10 start=disabled | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f | Out-Null
    Write-Log "Disabled SMBv1" "SUCCESS"
    
    # Enable SMB signing
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
    
    # Disable LLMNR
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f | Out-Null
    
    # Disable NetBIOS over TCP/IP
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
    foreach ($adapter in $adapters) {
        $adapter.SetTcpipNetbios(2) | Out-Null
    }
    
    # Remove dangerous default shares
    Write-Log "Removing dangerous default shares..."
    net share C:\ /delete 2>$null | Out-Null
    net share C:\Windows /delete 2>$null | Out-Null
    
    # Restrict unauthenticated RPC
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f | Out-Null
    
    # Disable BITS transfers (if aggressive)
    if ($Aggressive) {
        reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 0 /f | Out-Null
        reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f | Out-Null
    }
    
    Write-Log "Network security hardening complete" "SUCCESS"
}

# =============================================================================
# FIREWALL CONFIGURATION
# =============================================================================
function Configure-Firewall {
    Write-Log "=== FIREWALL CONFIGURATION ===" "INFO"
    
    # Start firewall service
    net start mpssvc | Out-Null
    
    # Enable firewall for all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
    
    # Set default actions
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
    
    # Enable comprehensive logging
    netsh advfirewall set Domainprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log | Out-Null
    netsh advfirewall set Domainprofile logging maxfilesize 20000 | Out-Null
    netsh advfirewall set Privateprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log | Out-Null
    netsh advfirewall set Privateprofile logging maxfilesize 20000 | Out-Null
    netsh advfirewall set Publicprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log | Out-Null
    netsh advfirewall set Publicprofile logging maxfilesize 20000 | Out-Null
    netsh advfirewall set Publicprofile logging droppedconnections enable | Out-Null
    netsh advfirewall set Publicprofile logging allowedconnections enable | Out-Null
    
    # Disable multicast/broadcast response
    netsh advfirewall firewall set multicastbroadcastresponse disable | Out-Null
    
    Write-Log "Firewall enabled with logging" "SUCCESS"
}

# =============================================================================
# RDP HARDENING
# =============================================================================
function Enable-RDPSecurity {
    Write-Log "=== RDP SECURITY ===" "INFO"
    
    # Enable RDP with NLA (Network Level Authentication)
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f | Out-Null
    
    # Require encrypted connections
    reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v fDisableEncryption /t REG_DWORD /d 0 /f | Out-Null
    
    # Disable Remote Assistance
    reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /v fAllowFullControl /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f | Out-Null
    
    # Set RDP session timeouts
    reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fResetBroken /t REG_DWORD /d 1 /f | Out-Null
    
    Write-Log "RDP hardened with NLA enforcement" "SUCCESS"
}

# =============================================================================
# UAC CONFIGURATION
# =============================================================================
function Enable-UAC {
    Write-Log "=== UAC CONFIGURATION ===" "INFO"
    
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f | Out-Null
    
    Write-Log "UAC enabled and configured" "SUCCESS"
}

# =============================================================================
# AUDITING
# =============================================================================
function Enable-Auditing {
    Write-Log "=== ENABLING COMPREHENSIVE AUDITING ===" "INFO"
    
    # Enable audit policy using subcategories
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f | Out-Null
    
    # Enable ALL auditing (comprehensive - may generate lots of logs)
    auditpol /set /category:* /success:enable /failure:enable | Out-Null
    
    Write-Log "Comprehensive auditing enabled" "SUCCESS"
}

# =============================================================================
# DISABLE DANGEROUS BACKDOORS
# =============================================================================
function Disable-Backdoors {
    Write-Log "=== DISABLING BACKDOOR MECHANISMS ===" "INFO"
    
    # Disable accessibility backdoors (sticky keys, etc.)
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f | Out-Null
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f | Out-Null
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f | Out-Null
    
    # Disable Cortana
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f | Out-Null
    
    Write-Log "Backdoor mechanisms disabled" "SUCCESS"
}

# =============================================================================
# SHOW HIDDEN FILES (helps find malware)
# =============================================================================
function Enable-FileVisibility {
    Write-Log "=== ENABLING FILE VISIBILITY ===" "INFO"
    
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f | Out-Null
    reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V HideFileExt /T REG_DWORD /D 0 /F | Out-Null
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /F | Out-Null
    
    Write-Log "Enabled visibility of hidden files and file extensions" "SUCCESS"
}

# =============================================================================
# ACTIVE DIRECTORY SPECIFIC HARDENING
# =============================================================================
function Enable-ADHardening {
    if (-not $isDC) { return }
    
    Write-Log "=== ACTIVE DIRECTORY HARDENING ===" "INFO"
    
    try {
        # Disable Kerberos delegation for all users (prevents privilege escalation)
        Write-Log "Disabling Kerberos delegation for users..."
        $Users = Get-ADUser -Filter * -Properties TrustedForDelegation -ErrorAction SilentlyContinue
        foreach ($User in $Users) {
            if ($User.TrustedForDelegation) {
                Set-ADUser -Identity $User -TrustedForDelegation $False -ErrorAction SilentlyContinue
                Write-Log "Disabled delegation for: $($User.Name)"
            }
        }
        
        # Disable RC4 for Kerberos (force AES)
        Write-Log "Disabling RC4 Kerberos encryption..."
        Get-ADUser -Filter * -ErrorAction SilentlyContinue | Set-ADUser -KerberosEncryptionType AES128,AES256 -ErrorAction SilentlyContinue
        
        # Note: Commented out Protected Users group add - this can break things
        # Add-ADGroupMember -Identity "Protected Users" -Members "Domain Users"
        
        Write-Log "AD hardening complete" "SUCCESS"
    } catch {
        Write-Log "AD hardening failed: $_" "ERROR"
    }
}

# =============================================================================
# IIS HARDENING
# =============================================================================
function Enable-IISHardening {
    if (-not $hasIIS) { return }
    
    Write-Log "=== IIS HARDENING ===" "INFO"
    
    try {
        Import-Module WebAdministration -ErrorAction Stop
        
        # Set all app pools to use ApplicationPoolIdentity
        Foreach($item in (Get-ChildItem IIS:\AppPools)) {
            $tempPath="IIS:\AppPools\"; $tempPath+=$item.name
            Set-ItemProperty -Path $tempPath -name processModel.identityType -value 4 -ErrorAction SilentlyContinue
        }
        
        # Disable directory browsing
        Foreach($item in (Get-ChildItem IIS:\Sites)) {
            $tempPath="IIS:\Sites\"; $tempPath+=$item.name
            Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -PSPath $tempPath -value False -ErrorAction SilentlyContinue
        }
        
        Write-Log "IIS hardening complete" "SUCCESS"
    } catch {
        Write-Log "IIS hardening failed: $_" "WARN"
    }
}

# =============================================================================
# PASSWORD CHANGES
# =============================================================================
function Change-AllPasswords {
    if (-not $ChangePasswords) { return }
    
    Write-Log "=== CHANGING ALL USER PASSWORDS ===" "WARN"
    
    if ([string]::IsNullOrEmpty($NewPassword)) {
        $securePassword = Read-Host "Enter new password for ALL users" -AsSecureString
    } else {
        $securePassword = ConvertTo-SecureString $NewPassword -AsPlainText -Force
    }
    
    # Change local users
    Get-LocalUser | ForEach-Object {
        try {
            Set-LocalUser -Name $_.Name -Password $securePassword -ErrorAction Stop
            Write-Log "Changed password for local user: $($_.Name)" "SUCCESS"
        } catch {
            Write-Log "Failed to change password for: $($_.Name)" "ERROR"
        }
    }
    
    # Change domain users (if DC)
    if ($isDC) {
        Get-ADUser -Filter * | ForEach-Object {
            try {
                Set-ADAccountPassword -Identity $_.SamAccountName -NewPassword $securePassword -Reset -ErrorAction Stop
                Write-Log "Changed password for domain user: $($_.SamAccountName)" "SUCCESS"
            } catch {
                Write-Log "Failed to change password for: $($_.SamAccountName)" "ERROR"
            }
        }
    }
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

Write-Log "=== STARTING HARDENING PROCESS ===" "INFO"

# Run all hardening functions
Enable-CredentialProtection
Enable-DefenderHardening
Enable-CVEMitigations
Enable-NetworkSecurity
Configure-Firewall
Enable-RDPSecurity
Enable-UAC
Enable-Auditing
Disable-Backdoors
Enable-FileVisibility
Enable-ADHardening
Enable-IISHardening
Change-AllPasswords

# Save errors to desktop
if ($Error.Count -gt 0) {
    $Error | Out-File $errorLog -Encoding utf8
    Write-Log "Errors logged to: $errorLog" "WARN"
}

# Update Defender signatures
Write-Log "Updating Windows Defender signatures..."
Update-MpSignature -ErrorAction SilentlyContinue

# Run system file checker and DISM (if aggressive)
if ($Aggressive) {
    Write-Log "Running system integrity checks..." "INFO"
    sc.exe config trustedinstaller start= auto | Out-Null
    Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -NoNewWindow -Wait
    Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -NoNewWindow -Wait
}

Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║                                                                 ║
║                  HARDENING COMPLETE!                           ║
║                                                                 ║
╚═══════════════════════════════════════════════════════════════╝

Log file: $logFile
Error log: $errorLog

CRITICAL NEXT STEPS:
1. Review the log file for any errors
2. Test that all services still work
3. Reboot the system to apply all changes
4. Monitor event logs for suspicious activity

"@ -ForegroundColor Green

Write-Log "=== HARDENING COMPLETE ===" "SUCCESS"

$reboot = Read-Host "Reboot now to apply all changes? (y/n)"
if ($reboot -eq 'y') {
    Write-Log "Rebooting system..." "INFO"
    shutdown /r /t 30 /c "Rebooting to apply security hardening"
}
