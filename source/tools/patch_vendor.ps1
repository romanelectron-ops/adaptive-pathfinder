#Requires -Version 5.1
<#
.SYNOPSIS
    Re-apply local patches to vendor/ after `go mod vendor`.

.DESCRIPTION
    sing-box's experimental/libbox/pidfd_android.go uses //go:linkname to os.checkPidfdOnce.
    That symbol only exists for GOOS=linux; on GOOS=android the link fails with
    "invalid reference to os.checkPidfdOnce". Android does not use pidfd at all
    (os/pidfd_other.go), so the file is reduced to its package clause.

    `go mod vendor` silently restores the original file; the guard test
    mobile/androidbridge/vendor_patch_test.go fails until this script is run.
    (tools/android/build_aar.ps1 applies the same patch to the module cache, because
    gomobile bind builds with -mod=mod.)

.EXAMPLE
    cd source; go mod vendor; .\tools\patch_vendor.ps1
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$f = Join-Path $root 'vendor\github.com\sagernet\sing-box\experimental\libbox\pidfd_android.go'
if (-not (Test-Path $f)) { throw "Not found: $f (run 'go mod vendor' first)" }
$content = "package libbox`n"
[System.IO.File]::WriteAllText($f, $content, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "patched: $f"
