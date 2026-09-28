#Requires -Version 5.1
<#
.SYNOPSIS
    Sync the public GitHub copy of APF from the local development tree.

.DESCRIPTION
    Development happens in a private local tree. The public repository is a separate
    folder that receives ONLY allow-listed content, scrubbed of personal data:

      1. Copy allow-listed directories/files (robocopy /MIR per component).
      2. Scrub text files with a PRIVATE replacement map that lives OUTSIDE the repo
         (literal string -> neutral placeholder).
      3. Gate: fail if any "block" pattern from the private map survives, if an IPv4
         address outside the reviewed allow-list is present, or if a file is too big.

    Nothing is committed or pushed by this script - it only prepares and verifies the
    working tree. Review the report, then commit.

.EXAMPLE
    .\sync_public.ps1 -Src <dev>\apf-dist -Out <publish>\adaptive-pathfinder -Map <publish>\_private\scrub_map.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Src,
    [Parameter(Mandatory)] [string]$Out,
    [Parameter(Mandatory)] [string]$Map,
    # Reviewed public IPv4 addresses allowed to stay (one per line, # comments allowed).
    [string]$IpAllow = '',
    [int]$MaxFileMB = 50
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Src)) { throw "Src not found: $Src" }
if (-not (Test-Path $Map)) { throw "Map not found: $Map" }
$outFull = [System.IO.Path]::GetFullPath($Out)
$mapFull = [System.IO.Path]::GetFullPath($Map)
if ($mapFull.StartsWith($outFull, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "The private map must NOT live inside the public repo folder."
}
New-Item -ItemType Directory -Force $Out | Out-Null

# ---- 1. Copy allow-listed content ------------------------------------------------------
$commonXF = @('*.exe', '*.dll', '*.so', '*.aar', '*.apk', '*.jar', '*.test', '*.out', '*.prof',
              '*.log', '*_log.txt', '*.syso', 'local.properties', 'sandbox_diagnosis.txt',
              'webui_token', 'server_identity.json', 'server_relay_credentials.json',
              '*.keystore', '*.jks', '*_cover.html', 'cover*.html', '*.cov', 'cov*.txt')
$commonXD = @('node_modules', 'build', '.gradle', 'dist', 'vendor', '.claude', '.memora', '.idea', '.vs')

function Copy-Tree([string]$from, [string]$to, [string[]]$xd = @(), [string[]]$xf = @()) {
    if (-not (Test-Path $from)) { Write-Host "  (skip, missing) $from"; return }
    $args = @($from, $to, '/MIR', '/NFL', '/NDL', '/NJH', '/NJS', '/NP', '/R:1', '/W:1')
    $args += '/XD'; $args += ($commonXD + $xd)
    $args += '/XF'; $args += ($commonXF + $xf)
    & robocopy @args | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE): $from" }
}

$s = Join-Path $Src 'source'
foreach ($d in 'cmd', 'internal', 'mobile', 'installer', 'scripts', '.github') {
    Copy-Tree (Join-Path $s $d) (Join-Path $Out "source\$d")
}
Copy-Tree (Join-Path $s 'tools') (Join-Path $Out 'source\tools') @() @('ipv6_restore_log.txt', '*_backup*', '*.bak')
Copy-Tree (Join-Path $s 'gui') (Join-Path $Out 'source\gui') @('bin') @('*.bak', 'go.mod.bak', 'go.sum.bak')
# gui/build/windows (icon + manifest) IS needed for the installer; build/bin is not.
Copy-Tree (Join-Path $s 'gui\build\windows') (Join-Path $Out 'source\gui\build\windows')
foreach ($f in 'go.mod', 'go.sum', 'Makefile') {
    if (Test-Path (Join-Path $s $f)) { Copy-Item (Join-Path $s $f) (Join-Path $Out "source\$f") -Force }
}
$a = Join-Path $Src 'android\android-project'
Copy-Tree (Join-Path $a 'app') (Join-Path $Out 'android\android-project\app') @('libs', 'jniLibs')
Copy-Tree (Join-Path $a 'gradle') (Join-Path $Out 'android\android-project\gradle')
foreach ($f in 'build.gradle', 'settings.gradle', 'gradle.properties') {
    if (Test-Path (Join-Path $a $f)) { Copy-Item (Join-Path $a $f) (Join-Path $Out "android\android-project\$f") -Force }
}

# ---- 2. Scrub ------------------------------------------------------------------------------
$m = Get-Content $Map -Raw -Encoding UTF8 | ConvertFrom-Json
$pairs = @($m.literal.PSObject.Properties | Sort-Object { $_.Name.Length } -Descending)
$textExt = @('.go', '.kt', '.kts', '.java', '.xml', '.gradle', '.properties', '.md', '.txt', '.ps1',
             '.psm1', '.bat', '.cmd', '.sh', '.nsi', '.nsh', '.json', '.yml', '.yaml', '.html', '.htm',
             '.js', '.ts', '.css', '.toml', '.mod', '.cfg', '.ini', '.wsb', '.pro', '.svg', '')
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$files = Get-ChildItem $Out -Recurse -File | Where-Object { $_.FullName -notmatch '\\\.git\\' }
$changed = 0
foreach ($f in $files) {
    if ($textExt -notcontains $f.Extension.ToLowerInvariant()) { continue }
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    $text = [System.IO.File]::ReadAllText($f.FullName)
    $orig = $text
    foreach ($p in $pairs) {
        $text = [regex]::Replace($text, [regex]::Escape($p.Name), [string]$p.Value.Replace('$', '$$'),
                                 [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    if ($text -ne $orig) {
        $enc = if ($hasBom) { New-Object System.Text.UTF8Encoding($true) } else { $utf8NoBom }
        [System.IO.File]::WriteAllText($f.FullName, $text, $enc)
        $changed++
    }
}
Write-Host "Scrubbed files: $changed"

# ---- 3. Gate ------------------------------------------------------------------------------
$problems = New-Object System.Collections.Generic.List[string]
$allowIps = @{}
if ($IpAllow -and (Test-Path $IpAllow)) {
    Get-Content $IpAllow | ForEach-Object { $l = ($_ -replace '#.*$', '').Trim(); if ($l) { $allowIps[$l] = $true } }
}
function Test-PrivateOrDocIp([string]$ip) {
    $o = $ip.Split('.') | ForEach-Object { [int]$_ }
    if ($o | Where-Object { $_ -gt 255 }) { return $true }  # not an IP (version string etc.)
    if ($o[0] -in 0, 10, 127, 255) { return $true }
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return $true }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $true }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $true }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $true }
    if ($o[0] -eq 192 -and $o[1] -eq 0 -and $o[2] -eq 2) { return $true }
    if ($o[0] -eq 198 -and $o[1] -eq 51 -and $o[2] -eq 100) { return $true }
    if ($o[0] -eq 203 -and $o[1] -eq 0 -and $o[2] -eq 113) { return $true }
    if ($o[0] -eq 198 -and ($o[1] -eq 18 -or $o[1] -eq 19)) { return $true }
    if ($o[0] -ge 224) { return $true }
    return $false
}
$ipSeen = @{}
foreach ($f in (Get-ChildItem $Out -Recurse -File | Where-Object { $_.FullName -notmatch '\\\.git\\' })) {
    if ($f.Length -gt $MaxFileMB * 1MB) { $problems.Add("TOO BIG: $($f.FullName) ($([math]::Round($f.Length/1MB,1)) MB)") }
    if ($textExt -notcontains $f.Extension.ToLowerInvariant()) { continue }
    $text = [System.IO.File]::ReadAllText($f.FullName)
    foreach ($b in $m.block) {
        foreach ($hit in [regex]::Matches($text, $b)) {
            $problems.Add("BLOCKED '$b' in $($f.FullName.Substring($outFull.Length)) : ...$($text.Substring([Math]::Max(0,$hit.Index-30), [Math]::Min(80, $text.Length-[Math]::Max(0,$hit.Index-30))) -replace '\s+',' ')...")
        }
    }
    foreach ($hit in [regex]::Matches($text, '(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])')) {
        $ip = $hit.Value
        if ((Test-PrivateOrDocIp $ip) -or $allowIps.ContainsKey($ip)) { continue }
        $key = "$ip|$($f.FullName.Substring($outFull.Length))"
        if (-not $ipSeen.ContainsKey($key)) { $ipSeen[$key] = $true; $problems.Add("UNREVIEWED IP $ip in $($f.FullName.Substring($outFull.Length))") }
    }
}

$total = (Get-ChildItem $Out -Recurse -File | Where-Object { $_.FullName -notmatch '\\\.git\\' } | Measure-Object Length -Sum)
Write-Host ("Files: {0}, size: {1:N1} MB" -f $total.Count, ($total.Sum / 1MB))
if ($problems.Count -gt 0) {
    Write-Host "GATE FAILED: $($problems.Count) problem(s):" -ForegroundColor Red
    $problems | Select-Object -First 200 | ForEach-Object { Write-Host "  $_" }
    exit 2
}
Write-Host "GATE PASSED: no personal data patterns, no unreviewed public IPs." -ForegroundColor Green
exit 0
