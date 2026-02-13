# Enable Scriptblock Logging
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host "[+] Successfully enabled PowerShell Script Block Logging" -ForegroundColor Green

# PowerShell Module Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"
Write-Host "[+] Successfully enabled PowerShell Module Logging" -ForegroundColor Green

# PowerShell Transcription
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PSTranscripts"
Write-Host "[+] Successfully enabled PowerShell Transcription (Output: C:\PSTranscripts)" -ForegroundColor Green

# Command Line in Process Creation Events (4688)
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
Write-Host "[+] Successfully enabled Command Line in Process Creation Events (Event ID 4688)" -ForegroundColor Green

# Process Creation Auditing (Event 4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Process Creation Auditing (Event ID 4688)" -ForegroundColor Green

# Process Termination Auditing (Event 4689)
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Process Termination Auditing (Event ID 4689)" -ForegroundColor Green

# Detects when one process opens a handle to another (precursor to injection)
# Event IDs 4656, 4658, 4660, 4663
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Handle Manipulation Auditing" -ForegroundColor Green

# Detects privilege escalation and token impersonation (Event ID 4703)
auditpol /set /subcategory:"Token Right Adjusted" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Token Right Adjusted Auditing (Event ID 4703)" -ForegroundColor Green

# Detects access to SAM database - credential dumping (Event ID 4661)
auditpol /set /subcategory:"SAM" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled SAM Access Auditing (Event ID 4661)" -ForegroundColor Green

# Logon/Logoff Events (4624, 4625, 4634)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Logoff" /success:enable | Out-Null
Write-Host "[+] Successfully enabled Logon/Logoff Events (Event IDs 4624, 4625, 4634)" -ForegroundColor Green

# Account Logon Events (4776, 4768, 4769)
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Account Logon Events (Event IDs 4776, 4768, 4769)" -ForegroundColor Green

# User Account Management (4720, 4722, 4724, 4726)
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled User Account Management (Event IDs 4720, 4722, 4724, 4726)" -ForegroundColor Green

# Security Group Management (4728, 4732, 4756)
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Security Group Management (Event IDs 4728, 4732, 4756)" -ForegroundColor Green

# Sensitive Privilege Use (4673, 4674)
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Sensitive Privilege Use (Event IDs 4673, 4674)" -ForegroundColor Green

# Scheduled Task Events (4698, 4699, 4700, 4701, 4702)
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Scheduled Task Events (Event IDs 4698, 4699, 4700, 4701, 4702)" -ForegroundColor Green

# Registry Auditing
auditpol /set /subcategory:"Registry" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Registry Auditing" -ForegroundColor Green

# File Share Access (5140, 5145)
auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled File Share Access (Event IDs 5140, 5145)" -ForegroundColor Green

# Network Connection Auditing (5156, 5157, 5158)
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Network Connection Auditing (Event IDs 5156, 5157, 5158)" -ForegroundColor Green

# Audit Policy Changes (4719)
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Audit Policy Changes (Event ID 4719)" -ForegroundColor Green

# Security System Extension (4610, 4611, 4614)
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Security System Extension (Event IDs 4610, 4611, 4614)" -ForegroundColor Green

# System Integrity Events (4612, 4615, 4616, 4618)
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled System Integrity Events (Event IDs 4612, 4615, 4616, 4618)" -ForegroundColor Green

# Kernel Object Auditing (Event 4656, 4658, 4660, 4663)
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable | Out-Null
Write-Host "[+] Successfully enabled Kernel Object Auditing (Detects process injection)" -ForegroundColor Green

# Install Sysmon
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) { Write-Host "[!] Sysmon already installed" -ForegroundColor Yellow; exit }

Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig.xml"

Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force
& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmonconfig.xml"

if ((Get-Service Sysmon64).Status -eq 'Running') { Write-Host "[+] Sysmon installed and running" -ForegroundColor Green } else { Write-Host "[!] Sysmon installed but not running - starting..." -ForegroundColor Yellow; Start-Service Sysmon64 }