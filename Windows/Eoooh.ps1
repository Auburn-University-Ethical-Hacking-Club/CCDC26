# SafeRun.ps1 - Wrapper for Run.ps1 that excludes Domain Controllers
#
# Usage:
#   .\SafeRun.ps1 -Connect
#   .\SafeRun.ps1 -Script "Hard.ps1" -Out ".\results"
#   .\SafeRun.ps1 -Script "Hard.ps1" -Out ".\results" -AlsoIncludeDCs

param(
    [Parameter(Mandatory=$false)]
    [String]$Script = '',

    [Parameter(Mandatory=$false)]
    [String]$Out = '',

    [Parameter(Mandatory=$false)]
    [switch]$Connect,

    [Parameter(Mandatory=$false)]
    [switch]$Repair,

    [Parameter(Mandatory=$false)]
    [string[]]$Include,

    [Parameter(Mandatory=$false)]
    [string[]]$Exclude,

    [Parameter(Mandatory=$false)]
    [String]$Admin,

    [Parameter(Mandatory=$false)]
    [switch]$NonDomain,

    [Parameter(Mandatory=$false)]
    [String]$Hosts = '',

    # NEW: Only include DCs if explicitly requested
    [Parameter(Mandatory=$false)]
    [switch]$AlsoIncludeDCs
)

# Get all Domain Controllers
if (-not $AlsoIncludeDCs) {
    Write-Host "[SAFE MODE] Automatically excluding Domain Controllers" -ForegroundColor Yellow
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
        
        Write-Host "[INFO] Domain Controllers that will be excluded:" -ForegroundColor Yellow
        $DCs | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        
        # Add DCs to exclusion list
        if ($Exclude) {
            $Exclude = $Exclude + $DCs
        } else {
            $Exclude = $DCs
        }
    }
    catch {
        Write-Host "[WARNING] Could not get DC list. Proceeding without DC exclusion." -ForegroundColor Red
        Write-Host "[WARNING] Use -Exclude parameter manually to exclude DCs!" -ForegroundColor Red
    }
} else {
    Write-Host "[DANGER MODE] Domain Controllers will be INCLUDED!" -ForegroundColor Red
    Start-Sleep -Seconds 3
}

# Build arguments for Run.ps1
$RunArgs = @{}

if ($Script) { $RunArgs.Script = $Script }
if ($Out) { $RunArgs.Out = $Out }
if ($Connect) { $RunArgs.Connect = $true }
if ($Repair) { $RunArgs.Repair = $true }
if ($Include) { $RunArgs.Include = $Include }
if ($Exclude) { $RunArgs.Exclude = $Exclude }
if ($Admin) { $RunArgs.Admin = $Admin }
if ($NonDomain) { $RunArgs.NonDomain = $true }
if ($Hosts) { $RunArgs.Hosts = $Hosts }

# Call the original Run.ps1
Write-Host "`n[INFO] Calling Run.ps1 with exclusions..." -ForegroundColor Green
& .\Run.ps1 @RunArgs
