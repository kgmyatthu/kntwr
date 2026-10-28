<#
.SYNOPSIS
  Packages KNTWR.exe + kntwr_runtime.dll into KNTWR-<Version>-windows-x86.zip with a SHA256SUMS.txt.

.DESCRIPTION
  Used by .github/workflows/release.yml and runnable locally.  Reads the Release build output (build\bin\Release for
  Visual Studio generators, build\bin for single-config generators such as Ninja), requires both binaries to carry
  ProductVersion == -Version, and writes a flat archive: KNTWR.exe, kntwr_runtime.dll, README.md, CHANGELOG.md.
  No user config.json and no PDB are ever included.

  Only script-owned paths are cleaned: <OutputDir>\.stage-<Version> and the two output files this script produces.
  OutputDir itself and anything else in it are left alone.

.PARAMETER Version
  X.Y.Z, must equal the ProductVersion of both binaries.
.PARAMETER BuildDir
  CMake build directory (default build/ci-x86).
.PARAMETER OutputDir
  Where the zip and SHA256SUMS.txt are written (default artifacts).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [string]$BuildDir = 'build/ci-x86',

    [string]$OutputDir = 'artifacts'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

function Resolve-RepoPath([string]$p) {
    if ([IO.Path]::IsPathRooted($p)) { return [IO.Path]::GetFullPath($p) }
    return [IO.Path]::GetFullPath((Join-Path $repoRoot $p))
}

$buildPath = Resolve-RepoPath $BuildDir
$outPath = Resolve-RepoPath $OutputDir
if (-not (Test-Path -LiteralPath $buildPath -PathType Container)) { throw "BuildDir not found: $buildPath" }

$binDir = $null
foreach ($candidate in @((Join-Path $buildPath 'bin\Release'), (Join-Path $buildPath 'bin'))) {
    if ((Test-Path -LiteralPath (Join-Path $candidate 'KNTWR.exe') -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $candidate 'kntwr_runtime.dll') -PathType Leaf)) {
        $binDir = $candidate
        break
    }
}
if (-not $binDir) { throw "KNTWR.exe and kntwr_runtime.dll not found under $buildPath\bin\Release or $buildPath\bin" }

foreach ($name in @('KNTWR.exe', 'kntwr_runtime.dll')) {
    $pe = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $binDir $name)).ProductVersion
    if (-not $pe) { throw "$name has no ProductVersion" }
    $pe = $pe.Trim([char]0).Trim()
    if ($pe -ne $Version) { throw "$name ProductVersion '$pe' does not match -Version '$Version'" }
}

foreach ($doc in @('README.md', 'CHANGELOG.md')) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $doc) -PathType Leaf)) { throw "$doc missing from repo root" }
}

$zipName = "KNTWR-$Version-windows-x86.zip"
$zipPath = Join-Path $outPath $zipName
$sumsPath = Join-Path $outPath 'SHA256SUMS.txt'
$stage = Join-Path $outPath ".stage-$Version"

# Script-owned cleanup only; refuse anything that does not resolve inside OutputDir.
function Remove-Owned([string]$path, [string]$root) {
    if (-not (Test-Path -LiteralPath $path)) { return }
    $full = [IO.Path]::GetFullPath($path)
    $rootFull = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
    if (-not $full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) { throw "refusing to delete outside OutputDir: $full" }
    Remove-Item -LiteralPath $full -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $outPath | Out-Null
Remove-Owned $stage $outPath
Remove-Owned $zipPath $outPath
Remove-Owned $sumsPath $outPath
New-Item -ItemType Directory -Force -Path $stage | Out-Null

try {
    Copy-Item -LiteralPath (Join-Path $binDir 'KNTWR.exe') -Destination $stage
    Copy-Item -LiteralPath (Join-Path $binDir 'kntwr_runtime.dll') -Destination $stage
    Copy-Item -LiteralPath (Join-Path $repoRoot 'README.md') -Destination $stage
    Copy-Item -LiteralPath (Join-Path $repoRoot 'CHANGELOG.md') -Destination $stage

    # Fixed order, flat entries.  Compress-Archive on a file list keeps entries at the archive root.
    $files = 'KNTWR.exe', 'kntwr_runtime.dll', 'README.md', 'CHANGELOG.md' | ForEach-Object { Join-Path $stage $_ }
    Compress-Archive -LiteralPath $files -DestinationPath $zipPath -CompressionLevel Optimal

    $hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($sumsPath, "$hash  $zipName`n", [Text.UTF8Encoding]::new($false))
}
finally {
    Remove-Owned $stage $outPath
}

Write-Host "Packaged $zipPath"
Write-Host "SHA-256  $hash"
