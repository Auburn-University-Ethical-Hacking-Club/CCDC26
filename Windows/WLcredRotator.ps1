# Requires -RunAsAdministrator
# Requires -Module ActiveDirectory
# usage syntax .\Rotate-Passwords.ps1 -x Administrator, krbtgt, Guest      to exclude usernames

param(
    [string[]]$x = @()
)

# Prompt for wordlist
$wordlist = Read-Host "Wordlist path"

# Validate
if (-not (Test-Path $wordlist)) {
    Write-Host "[!] File not found" -ForegroundColor Red
    exit
}

# Load and process
$lines = Get-Content $wordlist
$success = 0
$failed = 0
$skipped = 0

if ($x.Count -gt 0) {
    Write-Host "`n[*] Excluding: $($x -join ', ')" -ForegroundColor Yellow
}

Write-Host "`n[*] Rotating passwords...`n" -ForegroundColor Cyan

foreach ($line in $lines) {
    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
    
    $parts = $line.Split(':', 2)
    if ($parts.Count -ne 2) { $failed++; continue }
    
    $user = $parts[0].Trim()
    $pass = $parts[1].Trim()

    # Check exclusion list
    if ($x -contains $user) {
        Write-Host "[~] $user skipped (excluded)" -ForegroundColor Yellow
        $skipped++
        continue
    }
    
    try {
        $secPass = ConvertTo-SecureString $pass -AsPlainText -Force
        Set-ADAccountPassword -Identity $user -NewPassword $secPass -Reset -ErrorAction Stop
        Write-Host "[+] $user" -ForegroundColor Green
        $success++
    }
    catch {
        Write-Host "[-] $user : Failed" -ForegroundColor Red
        $failed++
    }
    
    Remove-Variable pass, secPass -ErrorAction SilentlyContinue
}

Write-Host "`n[+] Success: $success" -ForegroundColor Green
Write-Host "[-] Failed:  $failed" -ForegroundColor Red
Write-Host "[~] Skipped: $skipped" -ForegroundColor Yellow

# Cleanup
Remove-Variable lines, user, pass, secPass, parts -ErrorAction SilentlyContinue
Clear-History
[System.GC]::Collect()

$delete = Read-Host "`nDelete wordlist? (y/n)"
if ($delete -eq 'y') {
    $bytes = New-Object byte[] (Get-Item $wordlist).Length
    (New-Object Random).NextBytes($bytes)
    [System.IO.File]::WriteAllBytes($wordlist, $bytes)
    Remove-Item $wordlist -Force
    Write-Host "[+] Wordlist deleted" -ForegroundColor Green
}

Write-Host "`n[*] Done`n" -ForegroundColor Cyan