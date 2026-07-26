[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BuildDir,
    [ValidateSet('Release')][string]$Configuration = 'Release',
    [Parameter(Mandatory = $true)][string]$EvidenceDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
$markerBytes = $utf8.GetBytes("FaultLoom Windows Authority MVP v1`n")
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$build = [IO.Path]::GetFullPath($BuildDir).TrimEnd('\')
$evidence = [IO.Path]::GetFullPath($EvidenceDir).TrimEnd('\')
$smokeRoot = Join-Path $repository 'out\windows_authority\smoke-evidence'

if (-not ('FaultLoom.Capture.OwnedLeafSession' -as [type])) {
    $methods = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'capture_native_methods.cs'))
    $session = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'owned_leaf_session.cs'))
    Add-Type -TypeDefinition ($methods + "`n" + $session)
}

$parentSession = & (Join-Path $PSScriptRoot 'verify-roots.ps1') `
    -RepositoryRoot $repository -Mode Smoke -BuildDir $build -EvidenceDir $evidence `
    -RetainMutationParent
try {

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Smoke must run from a standard non-elevated token'
}

$release = Join-Path $build $Configuration
$expectedRelease = Join-Path (Join-Path $repository 'out\windows_authority\build') 'Release'
if (-not $release.Equals($expectedRelease, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Release binaries must resolve beneath the exact build leaf'
}
$binaryNames = @('faultloom_broker.exe', 'faultloom_ctl.exe', 'faultloom_reviewer.exe',
    'faultloom_integration_tests.exe')
$binaries = foreach ($name in $binaryNames) {
    $path = Join-Path $release $name
    if (-not [IO.File]::Exists($path)) { throw "Required Release binary is missing: $name" }
    $full = [IO.Path]::GetFullPath($path)
    if (-not $full.StartsWith($release + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release binary escaped the build leaf: $name"
    }
    $full
}

function Get-StaticAudit {
    $sourceFiles = Get-ChildItem (Join-Path $repository 'native\windows_authority\src') `
        -Recurse -File -Include *.cpp,*.h
    $oracleFile = Join-Path $repository 'native\windows_authority\tests\integration_oracle.cpp'
    $source = (($sourceFiles | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join "`n")
    $oracle = [IO.File]::ReadAllText($oracleFile)
    $forbiddenSource = @(
        '\bSC_MANAGER_ALL_ACCESS\b', '\bSERVICE_ALL_ACCESS\b', '\bSERVICE_CHANGE_CONFIG\b',
        '\bSERVICE_START\b', '\bSERVICE_STOP\b', '\bSERVICE_PAUSE_CONTINUE\b',
        '\bCreateServiceW?\b', '\bChangeServiceConfig', '\bDeleteService\b',
        '\bStartServiceW?\b', '\bControlService\b', '\bReg(Create|Set|Delete)',
        '\bFwpm', '\bWinHttp', '\bInternet(Open|Connect)', '\bsocket\s*\('
    )
    foreach ($pattern in $forbiddenSource) {
        if ($source -match $pattern) { throw "Forbidden production source capability: $pattern" }
    }
    if ($source -notmatch 'open_manager\(SC_MANAGER_CONNECT\)' -or
        $oracle -notmatch 'SERVICE_QUERY_CONFIG' -or $oracle -notmatch 'SERVICE_QUERY_STATUS') {
        throw 'Exact read-only SCM access masks are missing'
    }
    $objdump = 'C:\mingw64\bin\objdump.exe'
    if (-not [IO.File]::Exists($objdump)) { throw 'Import audit tool is missing' }
    $forbiddenImports = '(?i)(WS2_32|WINHTTP|WININET|URLMON|FWPUCLNT)\.dll|Reg(Set|Create|Delete)|Fwpm|CreateService|ChangeServiceConfig|DeleteService|StartService|ControlService'
    foreach ($binary in $binaries[0..2]) {
        $imports = (& $objdump -p $binary 2>&1) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw "Import audit failed: $binary" }
        if ($imports -match $forbiddenImports) { throw "Forbidden import found: $binary" }
    }
    return "STATIC_IMPORT_SOURCE_AUDIT_OK`nSCM_MASKS=SC_MANAGER_CONNECT,SERVICE_QUERY_CONFIG,SERVICE_QUERY_STATUS`nWHOLE_HOST_CLAIM=NONE`n"
}

function Get-Sha256Bytes([byte[]]$Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($Bytes)
        return (($digest | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $algorithm.Dispose()
    }
}

$tempName = '.smoke-' + [Guid]::NewGuid().ToString('N')
$temp = Join-Path $smokeRoot $tempName
$outputName = Split-Path -Leaf $evidence
$leaf = $null
$published = $false
try {
    $memberNames = [string[]]@('smoke.json', 'smoke.log', 'static-audit.txt',
        'SHA256SUMS.txt')
    $leaf = [FaultLoom.Capture.OwnedLeafSession]::Create($parentSession,
        $tempName, $markerBytes, $memberNames, 1048576, 4194304)
    $audit = Get-StaticAudit
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $binaries[3]
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Smoke supervisor did not start' }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(30000)) {
        $process.Kill($true)
        $process.WaitForExit()
        throw 'Smoke supervisor exceeded 30 seconds'
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($stdout.Length + $stderr.Length -gt 1048576) { throw 'Smoke log exceeded 1 MiB' }
    if ($process.ExitCode -ne 0) { throw "Smoke supervisor failed: $stderr" }
    $lines = @($stdout -split "`r?`n" | Where-Object { $_.Length -ne 0 })
    if ($lines.Count -ne 1 -or -not $lines[0].StartsWith('SMOKE_JSON=')) {
        throw 'Smoke supervisor emitted an invalid result line'
    }
    $jsonText = $lines[0].Substring(11)
    $result = $jsonText | ConvertFrom-Json
    if (-not $result.same_sid -or -not $result.distinct_pids -or
        -not $result.signatures_valid -or -not $result.pipes_gone -or
        -not $result.negative_matrix -or -not $result.supervisor_death -or
        -not $result.memory_limit) { throw 'Smoke result did not prove every required oracle' }
    $evidenceBytes = [ordered]@{
        'smoke.json' = $utf8.GetBytes($jsonText + "`n")
        'smoke.log' = $utf8.GetBytes($stdout + $stderr)
        'static-audit.txt' = $utf8.GetBytes($audit)
    }
    foreach ($entry in $evidenceBytes.GetEnumerator()) {
        $leaf.WriteMember($entry.Key, $entry.Value)
    }
    $hashLines = foreach ($name in [string[]]$evidenceBytes.Keys) {
        $hash = Get-Sha256Bytes $evidenceBytes[$name]
        "$hash  $name"
    }
    $leaf.WriteMember('SHA256SUMS.txt', $utf8.GetBytes(($hashLines -join "`n") + "`n"))
    $leaf.Validate($true)
    $leaf.Publish($outputName, $markerBytes)
    $published = $true
    [Console]::Out.WriteLine('SMOKE_OK')
    [Console]::Out.WriteLine("REVIEWER_KEY_SHA256=$($result.reviewer_key_sha256)")
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
