#Requires -RunAsAdministrator

$enabled = @(
    "WinRM"
    "SSH"
    "RDP"
    "IIS"
    "SMB"
    "SFTP"
    "ADWS"
    "DNS"
    "Kerberos"
    "Netlogon"
    "NTDS"
    "W32tm"
    "DFSR"
    "IsmServ"
    "ADCS"
    "NPS"
    "ADLDS"
)

$map = @{
    WinRM    = "WinRM"
    SSH      = "sshd"
    RDP      = "TermService"
    IIS      = "W3SVC"
    SMB      = "LanmanServer"
    SFTP     = "OpenSSHd"
    ADWS     = "ADWS"
    DNS      = "DNS"
    Kerberos = "kdc"
    Netlogon = "Netlogon"
    NTDS     = "NTDS"
    W32tm    = "W32Time"
    DFSR     = "DFSR"
    IsmServ  = "IsmServ"
    ADCS     = "certsvc"
    NPS      = "IAS"
    ADLDS    = "ADAM_Microsoft"
}

foreach ($svc in $enabled) {
    $s = Get-Service $map[$svc] -ErrorAction SilentlyContinue
    if     (!$s)                      { Write-Host "[-] $svc not installed" -ForegroundColor Red }
    elseif ($s.Status -eq 'Running')  { Write-Host "[+] $svc already running" -ForegroundColor Green }
    else   { Start-Service $map[$svc] -ErrorAction SilentlyContinue; Write-Host "[+] $svc started" -ForegroundColor Green }
}