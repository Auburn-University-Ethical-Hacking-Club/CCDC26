<#
.SYNOPSIS
  Scan files for PII and optionally mask or export matches.

.DESCRIPTION
  - Scans text/binary files (configurable extensions) or entire directories recursively.
  - Uses a set of regex patterns for common PII types (SSN, credit cards, emails, phone numbers, passport-ish IDs, DOB).
  - Produces report (CSV/JSON) with file, line, match, type, context.
  - Optionally masks matches in-place (backups saved) or writes masked copies to an output folder.

.WARNING
  - Regexes are heuristics. Expect false positives/negatives. Tune patterns for your data.
  - Always run in report-only mode first. Masking is destructive — backups are created automatically.
#>

param(
  [Parameter(Mandatory=$true)][string]$Path,
  [string[]]$IncludeExtensions = @(".txt",".log",".csv",".json",".xml",".ps1",".psm1",".config",".env"),
  [int]$MaxFileSizeMB = 20,
  [ValidateSet("Report","Mask","ExportCopy")] [string]$Action = "Report",
  [string]$ReportPath = "C:\Scripts\PII_Report.json",
  [string]$BackupFolder = "C:\Scripts\PII_Backups",
  [string]$MaskedCopyFolder = "C:\Scripts\PII_Masked",
  [switch]$Verbose
)

# ------------- PII regex library (tune to your needs) -------------
$PII_Patterns = @{
    "Email" = '(?i)([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})'
    # US SSN: 123-45-6789 or 123456789 (avoid matching 9-digit numbers in general too often)
    "SSN" = '(?<!\d)(?!000|666|9\d{2})(\d{3})[- ]?((?!00)\d{2})[- ]?((?!0000)\d{4})(?!\d)'
    # Credit Card (Visa/Master/Amex/Discover heuristics) - Luhn NOT enforced here (for performance)
    "CreditCard" = '(?<!\d)(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})(?!\d)'
    # US Phone numbers (various formats)
    "Phone" = '(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)'
    # Date of birth common patterns (MM/DD/YYYY, YYYY-MM-DD)
    "DOB" = '(?<!\d)(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[-/](19|20)\d{2}(?!\d)|(?<!\d)(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])(?!\d)'
    # Simple passport-like alpha-numeric (country-specifics vary): 6-9 alnum
    "PassportLike" = '(?<!\w)[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9](?!\w)'
}

# Create folders if needed
New-Item -Path $BackupFolder -ItemType Directory -Force | Out-Null
New-Item -Path $MaskedCopyFolder -ItemType Directory -Force | Out-Null
New-Item -Path (Split-Path $ReportPath) -ItemType Directory -Force | Out-Null

$reportEntries = @()

# find files
$files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
         Where-Object { $IncludeExtensions -contains $_.Extension.ToLower() -and ($_.Length/1MB -le $MaxFileSizeMB) }

if ($Verbose) { "Scanning $($files.Count) files..." }

foreach ($f in $files) {
    try {
        $content = Get-Content -Path $f.FullName -Raw -ErrorAction Stop
    } catch {
        if ($Verbose) { "Failed to read $($f.FullName): $_" }
        continue
    }

    foreach ($type in $PII_Patterns.Keys) {
        $regex = $PII_Patterns[$type]
        $matches = [regex]::Matches($content, $regex)
        if ($matches.Count -gt 0) {
            foreach ($m in $matches) {
                $entry = [PSCustomObject]@{
                    File = $f.FullName
                    Type = $type
                    Match = $m.Value
                    Index = $m.Index
                    Context = ($content.Substring([Math]::Max(0,$m.Index-40), [Math]::Min(120, $content.Length - [Math]::Max(0,$m.Index-40))))
                    TimeFound = (Get-Date).ToString("o")
                }
                $reportEntries += $entry
            }
        }
    }

    # Masking or export copy actions
    if ($Action -ne "Report" -and $reportEntries -and ($reportEntries | Where-Object { $_.File -eq $f.FullName })) {
        $fileEntries = $reportEntries | Where-Object { $_.File -eq $f.FullName }

        if ($Action -eq "Mask") {
            # backup original
            $bakPath = Join-Path $BackupFolder ($f.Name + "." + (Get-Date -Format "yyyyMMddHHmmss") + ".bak")
            Copy-Item -Path $f.FullName -Destination $bakPath -Force

            $maskedContent = $content
            foreach ($e in $fileEntries) {
                $placeholder = "[REDACTED-$($e.Type)]"
                # Perform a precise replace of the match text (first occurrence at that index)
                $before = $maskedContent.Substring(0, $e.Index)
                $after = $maskedContent.Substring($e.Index + $e.Match.Length)
                $maskedContent = $before + $placeholder + $after
            }
            # overwrite file
            $maskedContent | Set-Content -Path $f.FullName -Encoding utf8
        } elseif ($Action -eq "ExportCopy") {
            $dest = Join-Path $MaskedCopyFolder $f.Name
            $maskedContent = $content
            foreach ($e in $fileEntries) {
                $placeholder = "[REDACTED-$($e.Type)]"
                $before = $maskedContent.Substring(0, $e.Index)
                $after = $maskedContent.Substring($e.Index + $e.Match.Length)
                $maskedContent = $before + $placeholder + $after
            }
            $maskedContent | Set-Content -Path $dest -Force -Encoding utf8
        }
    }
}

# Save report
$reportEntries | ConvertTo-Json -Depth 4 | Set-Content -Path $ReportPath -Encoding utf8

if ($Verbose) { "PII scan complete. Results: $($reportEntries.Count) matches. Report at $ReportPath" }

# Print summary to console
[PSCustomObject]@{
    ScannedFiles = $files.Count
    MatchesFound = $reportEntries.Count
    Report = $ReportPath
}

