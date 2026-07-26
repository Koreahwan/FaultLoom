[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BuildDir,
    [ValidateSet('Release')][string]$Configuration = 'Release',
    [Parameter(Mandatory = $true)][string]$OutputDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$markerBytes = $utf8.GetBytes("FaultLoom Windows Authority MVP v1`n")
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..')).TrimEnd('\')
$build = [IO.Path]::GetFullPath($BuildDir).TrimEnd('\')
$output = [IO.Path]::GetFullPath($OutputDir).TrimEnd('\')
$packageRoot = Join-Path $repository 'out\windows_authority\package'

if (-not ('FaultLoom.Capture.OwnedLeafSession' -as [type])) {
    $methods = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'capture_native_methods.cs'))
    $session = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'owned_leaf_session.cs'))
    Add-Type -TypeDefinition ($methods + "`n" + $session)
}

$parentSession = & (Join-Path $PSScriptRoot 'verify-roots.ps1') `
    -RepositoryRoot $repository -Mode Package -BuildDir $build -OutputDir $output `
    -RetainMutationParent
try {
function Get-Sha256Bytes([byte[]]$Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return (($algorithm.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $algorithm.Dispose()
    }
}

function Assert-RegularFile([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { throw "Required package input is missing: $Path" }
    $facts = [FaultLoom.Roots.NativePath]::Inspect($Path)
    if (($facts.Attributes -band 0x400) -ne 0 -or $facts.LinkCount -ne 1) {
        throw "Non-regular package input rejected: $Path"
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

function Get-Manifest([FaultLoom.Capture.OwnedLeafSession]$Leaf, [string[]]$Names) {
    $entries = foreach ($name in $Names) {
        $bytes = $Leaf.ReadMember($name)
        $size = $bytes.Length.ToString(
            [Globalization.CultureInfo]::InvariantCulture)
        '{"filename":"' + $name + '","size":' + $size + ',"sha256":"' +
            (Get-Sha256Bytes $bytes) + '"}'
    }
    return '{"schema_version":1,"architecture":"x64","configuration":"Release",' +
        '"protocol_version":1,"install_authorized":false,"files":[' +
        ($entries -join ',') + "]}`n"
}

function Get-Checksums([FaultLoom.Capture.OwnedLeafSession]$Leaf, [string[]]$Names) {
    return (($Names | ForEach-Object { (Get-Sha256Bytes $Leaf.ReadMember($_)) + '  ' + $_ }) -join
        "`n") + "`n"
}

$template = Join-Path $repository 'native\windows_authority\package\package-manifest.template.json'
$expectedTemplate = $utf8.GetBytes(
    "{`"schema_version`":1,`"architecture`":`"x64`",`"configuration`":`"Release`",`"protocol_version`":1,`"install_authorized`":false,`"files`":[]}`n")
Assert-RegularFile $template
$actualTemplate = [IO.File]::ReadAllBytes($template)
if ($actualTemplate.Length -ne $expectedTemplate.Length) { throw 'Manifest template is not canonical' }
for ($index = 0; $index -lt $actualTemplate.Length; ++$index) {
    if ($actualTemplate[$index] -ne $expectedTemplate[$index]) {
        throw 'Manifest template is not canonical'
    }
}

$sources = [ordered]@{
    'INSTALL-GATE.md' = Join-Path $repository 'native\windows_authority\package\INSTALL-GATE.md'
    'README.md' = Join-Path $repository 'native\windows_authority\README.md'
    'faultloom_broker.exe' = Join-Path $build 'Release\faultloom_broker.exe'
    'faultloom_ctl.exe' = Join-Path $build 'Release\faultloom_ctl.exe'
    'faultloom_reviewer.exe' = Join-Path $build 'Release\faultloom_reviewer.exe'
}
foreach ($source in $sources.Values) { Assert-RegularFile $source }
Assert-Markdown $sources['INSTALL-GATE.md']
Assert-Markdown $sources['README.md']

$tempName = '.package-' + [Guid]::NewGuid().ToString('N')
$temp = Join-Path $packageRoot $tempName
$outputName = Split-Path -Leaf $output
$leaf = $null
$published = $false
try {
    $memberNames = [string[]]($sources.Keys + @('package-manifest.json', 'SHA256SUMS.txt'))
    $leaf = [FaultLoom.Capture.OwnedLeafSession]::Create($parentSession,
        $tempName, $markerBytes, $memberNames, 4194304, 16777216)
    foreach ($entry in $sources.GetEnumerator()) {
        $leaf.WriteMember($entry.Key, [IO.File]::ReadAllBytes($entry.Value))
    }
    $inputNames = [string[]]$sources.Keys
    $manifestOutput = @(Get-Manifest $leaf $inputNames)
    if ($manifestOutput.Count -ne 1) {
        throw "Manifest builder returned $($manifestOutput.Count) values"
    }
    if ($manifestOutput[0] -isnot [string]) {
        throw "Manifest builder returned type $($manifestOutput[0].GetType().FullName)"
    }
    [string]$manifestText = $manifestOutput[0]
    $leaf.WriteMember('package-manifest.json', $utf8.GetBytes($manifestText))
    $checksumNames = [string[]]($inputNames + 'package-manifest.json')
    $leaf.WriteMember('SHA256SUMS.txt', $utf8.GetBytes((Get-Checksums $leaf $checksumNames)))
    $leaf.Validate($true)
    & (Join-Path $PSScriptRoot 'verify-package.ps1') -PackageDir $temp | Out-Null
    $leaf.Publish($outputName, $markerBytes)
    $published = $true
    [Console]::Out.WriteLine('PACKAGE_OK')
} finally {
    if ($null -ne $leaf) {
        try {
            if (-not $published) { $leaf.Cleanup() }
        } finally {
            $leaf.Dispose()
        }
    }
}
} finally {
    if ($null -ne $parentSession) { $parentSession.Dispose() }
}
