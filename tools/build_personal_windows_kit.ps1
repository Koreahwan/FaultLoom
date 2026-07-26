[CmdletBinding()]
param(
    [switch]$SkipCliBuild,
    [switch]$SkipDependencyInstall,
    [string]$AuthorityPackage
)

$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($AuthorityPackage)) {
    $AuthorityPackage = Join-Path $repository `
        'out\windows_authority\package\r4-retained-transaction'
}
$authority = [IO.Path]::GetFullPath($AuthorityPackage)

if (-not $SkipCliBuild) {
    $arguments = @{}
    if ($SkipDependencyInstall) { $arguments.SkipDependencyInstall = $true }
    & (Join-Path $PSScriptRoot 'build_personal_windows_cli.ps1') @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Personal CLI build failed' }
}

$cli = Join-Path $repository 'out\personal-cli\release\faultloom.exe'
if (-not [IO.File]::Exists($cli)) { throw 'Personal CLI executable is missing' }
& (Join-Path $repository 'native\windows_authority\tools\verify-package.ps1') `
    -PackageDir $authority
if ($LASTEXITCODE -ne 0) { throw 'Windows authority package verification failed' }

$outputRoot = Join-Path $repository 'out\personal-kit'
$release = Join-Path $outputRoot 'release'
$markerName = '.faultloom-personal-kit-v1'
if ([IO.Directory]::Exists($release)) {
    if (-not [IO.File]::Exists((Join-Path $release $markerName))) {
        throw "Refusing to replace unowned output directory: $release"
    }
    Remove-Item -LiteralPath $release -Recurse -Force
}
[IO.Directory]::CreateDirectory($release) | Out-Null
[IO.File]::WriteAllText(
    (Join-Path $release $markerName),
    "FaultLoom personal Windows kit v1`n",
    [Text.UTF8Encoding]::new($false)
)

[IO.File]::Copy($cli, (Join-Path $release 'faultloom.exe'), $true)
[IO.File]::Copy(
    (Join-Path $repository 'docs\PERSONAL_WINDOWS_KIT.md'),
    (Join-Path $release 'README.md'),
    $true
)
$authorityOutput = Join-Path $release 'windows-authority'
[IO.Directory]::CreateDirectory($authorityOutput) | Out-Null
$authorityMembers = @(
    'faultloom_broker.exe',
    'faultloom_ctl.exe',
    'faultloom_reviewer.exe',
    'README.md',
    'INSTALL-GATE.md',
    'package-manifest.json',
    'SHA256SUMS.txt'
)
foreach ($name in $authorityMembers) {
    [IO.File]::Copy(
        (Join-Path $authority $name),
        (Join-Path $authorityOutput $name),
        $true
    )
}

function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try {
            return -join ($algorithm.ComputeHash($stream) |
                ForEach-Object { $_.ToString('x2') })
        } finally {
            $algorithm.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

$lines = Get-ChildItem -LiteralPath $release -Recurse -File |
    Where-Object { $_.FullName -ne (Join-Path $release 'SHA256SUMS.txt') } |
    ForEach-Object {
        $relative = $_.FullName.Substring($release.Length + 1).Replace('\', '/')
        [pscustomobject]@{ Relative = $relative; Hash = Get-Sha256 $_.FullName }
    } |
    Sort-Object Relative |
    ForEach-Object { "$($_.Hash)  $($_.Relative)" }
[IO.File]::WriteAllText(
    (Join-Path $release 'SHA256SUMS.txt'),
    (($lines -join "`n") + "`n"),
    [Text.UTF8Encoding]::new($false)
)

& (Join-Path $release 'faultloom.exe') doctor --json
if ($LASTEXITCODE -ne 0) { throw 'Bundled CLI doctor failed' }
& (Join-Path $authorityOutput 'faultloom_ctl.exe') local ping
if ($LASTEXITCODE -ne 0) { throw 'Bundled Windows authority ping failed' }

Write-Output "READY $release"
