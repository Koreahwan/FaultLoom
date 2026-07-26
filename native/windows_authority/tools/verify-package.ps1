[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$PackageDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..')).TrimEnd('\')
$package = [IO.Path]::GetFullPath($PackageDir).TrimEnd('\')
& (Join-Path $PSScriptRoot 'verify-roots.ps1') -RepositoryRoot $repository -Mode Package `
    -PackageDir $package

function Get-Sha256([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        return (($algorithm.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $stream.Dispose()
        $algorithm.Dispose()
    }
}

function Assert-RegularMember([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { throw "Missing regular package member: $Path" }
    $facts = [FaultLoom.Roots.NativePath]::Inspect($Path)
    if (($facts.Attributes -band 0x400) -ne 0 -or $facts.LinkCount -ne 1) {
        throw "Reparse or multiply-linked package member rejected: $Path"
    }
}

function Assert-Markdown([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0 -or $bytes[$bytes.Length - 1] -ne 10 -or
        ($bytes.Length -gt 1 -and $bytes[$bytes.Length - 2] -eq 10) -or
        ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and
            $bytes[2] -eq 0xBF)) { throw "Markdown encoding rejected: $Path" }
    $text = $utf8.GetString($bytes)
    if ($text.Contains("`r")) { throw "Markdown must use LF line endings: $Path" }
}

function Get-Facts([string]$Name) {
    $path = Join-Path $package $Name
    Assert-RegularMember $path
    return [pscustomobject]@{
        Name = $Name
        Size = ([IO.FileInfo]::new($path)).Length
        Hash = Get-Sha256 $path
    }
}

function Get-Manifest([object[]]$Facts) {
    $entries = foreach ($fact in $Facts) {
        $size = $fact.Size.ToString([Globalization.CultureInfo]::InvariantCulture)
        '{"filename":"' + $fact.Name + '","size":' + $size + ',"sha256":"' +
            $fact.Hash + '"}'
    }
    return '{"schema_version":1,"architecture":"x64","configuration":"Release",' +
        '"protocol_version":1,"install_authorized":false,"files":[' +
        ($entries -join ',') + "]}`n"
}

function Assert-ExactBytes([string]$Path, [string]$Expected, [string]$Label) {
    $actual = [IO.File]::ReadAllBytes($Path)
    $wanted = $utf8.GetBytes($Expected)
    if ($actual.Length -ne $wanted.Length) {
        throw "$Label is not canonical: actual_length=$($actual.Length) expected_length=$($wanted.Length)"
    }
    for ($index = 0; $index -lt $actual.Length; ++$index) {
        if ($actual[$index] -ne $wanted[$index]) {
            throw "$Label is not canonical: first_difference=$index"
        }
    }
}

function Find-DumpBin {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not [IO.File]::Exists($vswhere)) { throw 'vswhere.exe is missing' }
    $installation = (& $vswhere -latest -products '*' -requires `
        Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace($installation)) { throw 'MSVC tools are missing' }
    $tools = @(Get-ChildItem (Join-Path $installation 'VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe') `
        -File | Sort-Object FullName -Descending)
    if ($tools.Count -eq 0) { throw 'dumpbin.exe is missing' }
    return $tools[0].FullName
}

function Assert-ReleaseBinary([string]$DumpBin, [string]$Path) {
    $headers = (& $DumpBin /headers $Path 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $headers -notmatch '(?m)^\s*8664 machine \(x64\)\s*$') {
        throw "Non-x64 package binary rejected: $Path"
    }
    $dependents = (& $DumpBin /dependents $Path 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $dependents -match
        '(?i)\b(VCRUNTIME[^\s]*|MSVCP[^\s]*|UCRTBASE|MSVCR[^\s]*|api-ms-win-crt-[^\s]*)\.dll\b') {
        throw "Dynamic MSVC runtime dependency rejected: $Path"
    }
}

$memberNames = @('faultloom_broker.exe', 'faultloom_ctl.exe', 'faultloom_reviewer.exe',
    'README.md', 'INSTALL-GATE.md', 'package-manifest.json', 'SHA256SUMS.txt')
$entries = @([IO.Directory]::GetFileSystemEntries($package))
if ($entries.Count -ne $memberNames.Count) { throw 'Package must contain exactly seven members' }
foreach ($entry in $entries) {
    $name = Split-Path -Leaf $entry
    if ($memberNames -cnotcontains $name) { throw "Unexpected package member: $name" }
    Assert-RegularMember $entry
}
Assert-Markdown (Join-Path $package 'INSTALL-GATE.md')
Assert-Markdown (Join-Path $package 'README.md')

$inputNames = @('INSTALL-GATE.md', 'README.md', 'faultloom_broker.exe', 'faultloom_ctl.exe',
    'faultloom_reviewer.exe')
$inputFacts = @($inputNames | ForEach-Object { Get-Facts $_ })
Assert-ExactBytes (Join-Path $package 'package-manifest.json') (Get-Manifest $inputFacts) `
    'package-manifest.json'
$checksumNames = @($inputNames + 'package-manifest.json')
$checksumFacts = @($checksumNames | ForEach-Object { Get-Facts $_ })
$checksumText = (($checksumFacts | ForEach-Object { $_.Hash + '  ' + $_.Name }) -join "`n") + "`n"
Assert-ExactBytes (Join-Path $package 'SHA256SUMS.txt') $checksumText 'SHA256SUMS.txt'

$secondInputFacts = @($inputNames | ForEach-Object { Get-Facts $_ })
$secondChecksumFacts = @($checksumNames | ForEach-Object { Get-Facts $_ })
for ($index = 0; $index -lt $inputFacts.Count; ++$index) {
    if ($inputFacts[$index].Size -ne $secondInputFacts[$index].Size -or
        $inputFacts[$index].Hash -cne $secondInputFacts[$index].Hash) {
        throw "Package input changed during verification: $($inputFacts[$index].Name)"
    }
}
for ($index = 0; $index -lt $checksumFacts.Count; ++$index) {
    if ($checksumFacts[$index].Size -ne $secondChecksumFacts[$index].Size -or
        $checksumFacts[$index].Hash -cne $secondChecksumFacts[$index].Hash) {
        throw "Checksum member changed during verification: $($checksumFacts[$index].Name)"
    }
}

$dumpbin = Find-DumpBin
foreach ($name in $memberNames | Where-Object { $_.EndsWith('.exe') }) {
    Assert-ReleaseBinary $dumpbin (Join-Path $package $name)
}
[Console]::Out.WriteLine('PACKAGE_VERIFY_OK')
