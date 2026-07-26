[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$OutputDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$stopwatch = [Diagnostics.Stopwatch]::StartNew()

function Get-CaptureMarkerBytes {
    return [Text.UTF8Encoding]::new($false).GetBytes("FaultLoom Windows Authority MVP v1`n")
}

function Import-CaptureLeafNative([string]$ToolRoot) {
    if (-not ('FaultLoom.Capture.CaptureLeafSession' -as [type])) {
        $methods = [IO.File]::ReadAllText((Join-Path $ToolRoot 'capture_native_methods.cs'))
        $session = [IO.File]::ReadAllText((Join-Path $ToolRoot 'capture_leaf_session.cs'))
        $io = [IO.File]::ReadAllText((Join-Path $ToolRoot 'capture_leaf_io.cs'))
        Add-Type -TypeDefinition ($methods + "`n" + $session + "`n" + $io)
    }
}

$toolRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $toolRoot 'verify-roots.ps1') -RepositoryRoot $RepositoryRoot -Mode Baseline -OutputDir $OutputDir
Import-CaptureLeafNative $toolRoot

$repository = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
$output = [IO.Path]::GetFullPath($OutputDir).TrimEnd([IO.Path]::DirectorySeparatorChar)
$baselineRoot = Join-Path $repository 'out\windows_authority\baseline'
$tempName = '.capture-' + [Guid]::NewGuid().ToString('N')
$outputName = Split-Path -Leaf $output
$markerBytes = Get-CaptureMarkerBytes
$utf8 = [Text.UTF8Encoding]::new($false)
$job = $null
$leaf = $null
$published = $false

try {
    $leaf = [FaultLoom.Capture.CaptureLeafSession]::Create($baselineRoot, $tempName, $markerBytes)
    $job = Start-Job -ScriptBlock {
        Add-Type -AssemblyName System.ServiceProcess
        $names = @('BFE', 'EventLog', 'WinDefend')
        $services = foreach ($name in $names) {
            $controller = [ServiceProcess.ServiceController]::new($name, '.')
            try {
                [pscustomobject][ordered]@{
                    name = $controller.ServiceName
                    start_type = $controller.StartType.ToString()
                    status = $controller.Status.ToString()
                }
            } finally {
                $controller.Dispose()
            }
        }
        [pscustomobject][ordered]@{
            services = @($services)
            host = [pscustomobject][ordered]@{
                machine_name = [Environment]::MachineName
                os_version = [Environment]::OSVersion.Version.ToString()
                os_architecture = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
            }
        }
    }

    $remaining = [Math]::Max(0.0, 5.0 - $stopwatch.Elapsed.TotalSeconds)
    if (-not (Wait-Job -Job $job -Timeout $remaining)) { throw 'Baseline capture exceeded five seconds' }
    if ($job.State -ne 'Completed') { throw "Baseline capture job failed: $($job.State)" }
    $captures = @(Receive-Job -Job $job)
    if ($captures.Count -ne 1) { throw 'Baseline capture returned an invalid result' }
    $capture = $captures[0]

    $serviceJson = ($capture.services | ConvertTo-Json -Depth 4 -Compress) + "`n"
    $hostJson = ($capture.host | ConvertTo-Json -Depth 3 -Compress) + "`n"
    $files = [ordered]@{
        'host.json' = $utf8.GetBytes($hostJson)
        'services.json' = $utf8.GetBytes($serviceJson)
    }
    $total = 0
    foreach ($entry in $files.GetEnumerator()) {
        if ($entry.Value.Length -gt 262144) { throw "Baseline file exceeds 256 KiB: $($entry.Key)" }
        $total += $entry.Value.Length
        $leaf.WriteMember($entry.Key, $entry.Value)
    }

    $hashLines = foreach ($name in @('host.json', 'services.json')) {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = $sha.ComputeHash($files[$name]) } finally { $sha.Dispose() }
        ([BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant() + '  ' + $name)
    }
    $hashBytes = $utf8.GetBytes(($hashLines -join "`n") + "`n")
    if ($hashBytes.Length -gt 262144) { throw 'baseline.sha256 exceeds 256 KiB' }
    $total += $hashBytes.Length
    if ($total -gt 1048576) { throw 'Baseline publication exceeds 1 MiB' }
    $leaf.WriteMember('baseline.sha256', $hashBytes)

    if ($stopwatch.Elapsed.TotalSeconds -gt 5.0) { throw 'Baseline capture exceeded five seconds' }
    $leaf.Publish($outputName, $markerBytes)
    $published = $true
    [Console]::Out.WriteLine('BASELINE_CAPTURE_OK')
} finally {
    if ($null -ne $job) {
        if ($job.State -notin @('Completed', 'Failed', 'Stopped')) { Stop-Job -Job $job }
        Remove-Job -Job $job -Force
    }
    if ($null -ne $leaf) {
        if (-not $published) { $leaf.Cleanup() }
        $leaf.Dispose()
    }
}
