#Requires -Version 5.1
<#
.SYNOPSIS
    Privacy gate for release artifacts (installers, APK, binaries) before publishing.

.DESCRIPTION
    Go embeds absolute source paths into binaries unless built with -trimpath, which can
    leak the build machine's user name and folder layout. This script scans each artifact
    for the "block" patterns of the PRIVATE scrub map (kept outside the repository):
      * .exe/.dll/.so/.bin and other files - raw byte scan (ASCII and UTF-16LE);
      * .apk/.aar/.zip/.jar - every entry inside the archive is scanned.
    NSIS installers are LZMA-compressed; scan the payload binaries BEFORE packaging.

    Exit code 0 = clean, 2 = at least one hit (do NOT publish).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string[]]$Path,
    [Parameter(Mandatory)] [string]$Map
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$patterns = @((Get-Content $Map -Raw -Encoding UTF8 | ConvertFrom-Json).block)
$bad = 0

function Test-Bytes([byte[]]$bytes, [string]$label) {
    $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
    $utf16 = [System.Text.Encoding]::Unicode.GetString($bytes)
    $found = @()
    foreach ($p in $patterns) {
        $c = ([regex]::Matches($ascii, $p)).Count + ([regex]::Matches($utf16, $p)).Count
        if ($c -gt 0) { $found += "'$p' x$c" }
    }
    if ($found.Count -gt 0) { Write-Host "  LEAK  $label : $($found -join ', ')" -ForegroundColor Red; return $false }
    return $true
}

foreach ($p in $Path) {
    foreach ($f in (Get-Item $p)) {
        $ext = $f.Extension.ToLowerInvariant()
        if ($ext -in '.apk', '.aar', '.zip', '.jar') {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($f.FullName)
            try {
                $ok = $true
                foreach ($e in $zip.Entries) {
                    if ($e.Length -eq 0) { continue }
                    $ms = New-Object System.IO.MemoryStream
                    $st = $e.Open(); $st.CopyTo($ms); $st.Dispose()
                    if (-not (Test-Bytes $ms.ToArray() "$($f.Name)!$($e.FullName)")) { $ok = $false }
                }
                if ($ok) { Write-Host "  clean $($f.Name) ($($zip.Entries.Count) entries)" } else { $bad++ }
            } finally { $zip.Dispose() }
        } else {
            if (Test-Bytes ([System.IO.File]::ReadAllBytes($f.FullName)) $f.Name) { Write-Host "  clean $($f.Name)" } else { $bad++ }
        }
    }
}
if ($bad -gt 0) { Write-Host "ARTIFACT GATE FAILED: $bad artifact(s) leak personal data." -ForegroundColor Red; exit 2 }
Write-Host "ARTIFACT GATE PASSED." -ForegroundColor Green
exit 0
