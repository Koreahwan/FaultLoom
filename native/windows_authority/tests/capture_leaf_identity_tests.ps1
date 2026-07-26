[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [switch]$InterruptionChild,
    [string]$InterruptionName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Condition([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Bytes([byte[]]$Actual, [byte[]]$Expected, [string]$Message) {
    Assert-Condition ($Actual.Length -eq $Expected.Length) $Message
    for ($index = 0; $index -lt $Actual.Length; ++$index) {
        Assert-Condition ($Actual[$index] -eq $Expected[$index]) $Message
    }
}

function Remove-TestJunction([string]$Path) {
    cmd.exe /d /c rmdir $Path
    if ($LASTEXITCODE -ne 0) { throw 'junction fixture cleanup failed' }
}

$repository = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
$tools = Join-Path $repository 'native\windows_authority\tools'
$nativeMethods = Join-Path $tools 'capture_native_methods.cs'
$nativeSession = Join-Path $tools 'capture_leaf_session.cs'
$nativeIo = Join-Path $tools 'capture_leaf_io.cs'
Assert-Condition ([IO.File]::Exists($nativeMethods)) 'handle-bound native methods are missing'
Assert-Condition ([IO.File]::Exists($nativeSession)) 'handle-bound capture session is missing'
Assert-Condition ([IO.File]::Exists($nativeIo)) 'handle-bound capture I/O is missing'
if (-not ('FaultLoom.Capture.CaptureLeafSession' -as [type])) {
    $source = [IO.File]::ReadAllText($nativeMethods) + "`n" + [IO.File]::ReadAllText($nativeSession) +
        "`n" + [IO.File]::ReadAllText($nativeIo)
    Add-Type -TypeDefinition $source
}

$verify = Join-Path $tools 'verify-roots.ps1'
$baseline = Join-Path $repository 'out\windows_authority\baseline'
& $verify -RepositoryRoot $repository -Mode Baseline -OutputDir (Join-Path $baseline 'identity-test-probe') | Out-Null
$markerBytes = [Text.UTF8Encoding]::new($false).GetBytes("FaultLoom Windows Authority MVP v1`n")

if ($InterruptionChild) {
    $childSession = [FaultLoom.Capture.CaptureLeafSession]::Create(
        $baseline, $InterruptionName, $markerBytes)
    $childSession.WriteMember('host.json', [byte[]](1, 2, 3))
    [Console]::Out.WriteLine('INTERRUPTION_READY')
    [Console]::Out.Flush()
    Start-Sleep -Seconds 30
    $childSession.Dispose()
    exit 0
}

$directoryCollisionName = '.capture-dddddddddddddddddddddddddddddddd'
$directoryCollisionPath = Join-Path $baseline $directoryCollisionName
$directoryCollisionMarker = Join-Path $baseline ('.' + $directoryCollisionName + '.faultloom-owned-v1')
$directorySentinel = Join-Path $directoryCollisionPath 'foreign.txt'
[IO.Directory]::CreateDirectory($directoryCollisionPath) | Out-Null
[IO.File]::WriteAllBytes($directorySentinel, [byte[]](4, 5, 6))
try {
    $rejected = $false
    try {
        $unused = [FaultLoom.Capture.CaptureLeafSession]::Create($baseline, $directoryCollisionName, $markerBytes)
        $unused.Dispose()
    } catch {
        $rejected = $true
    }
    Assert-Condition $rejected 'directory collision was accepted'
    Assert-Condition (-not [IO.File]::Exists($directoryCollisionMarker)) 'directory-create failure left a marker'
    Assert-Bytes ([IO.File]::ReadAllBytes($directorySentinel)) ([byte[]](4, 5, 6)) 'foreign directory changed'
} finally {
    if ([IO.File]::Exists($directorySentinel)) { [IO.File]::Delete($directorySentinel) }
    if ([IO.Directory]::Exists($directoryCollisionPath)) { [IO.Directory]::Delete($directoryCollisionPath) }
    if ([IO.File]::Exists($directoryCollisionMarker)) { [IO.File]::Delete($directoryCollisionMarker) }
}

$collisionName = '.capture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$collisionPath = Join-Path $baseline $collisionName
$collisionMarker = Join-Path $baseline ('.' + $collisionName + '.faultloom-owned-v1')
$foreignMarkerBytes = [byte[]](9, 9, 9)
[IO.File]::WriteAllBytes($collisionMarker, $foreignMarkerBytes)
try {
    $rejected = $false
    try {
        $unused = [FaultLoom.Capture.CaptureLeafSession]::Create($baseline, $collisionName, $markerBytes)
        $unused.Dispose()
    } catch {
        $rejected = $true
    }
    Assert-Condition $rejected 'marker collision was accepted'
    Assert-Condition (-not [IO.Directory]::Exists($collisionPath)) 'directory-create rollback left a temporary leaf'
    Assert-Bytes ([IO.File]::ReadAllBytes($collisionMarker)) $foreignMarkerBytes 'foreign marker changed'
} finally {
    if ([IO.Directory]::Exists($collisionPath)) { [IO.Directory]::Delete($collisionPath) }
    [IO.File]::Delete($collisionMarker)
}

$beforeWriteName = '.capture-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
$beforeWritePath = Join-Path $baseline $beforeWriteName
$beforeWriteStash = Join-Path $baseline 'identity-before-write-stash'
$beforeWriteMarker = Join-Path $baseline ('.' + $beforeWriteName + '.faultloom-owned-v1')
$beforeWriteSession = [FaultLoom.Capture.CaptureLeafSession]::Create(
    $baseline, $beforeWriteName, $markerBytes)
try {
    $moveRejected = $false
    try { [IO.Directory]::Move($beforeWritePath, $beforeWriteStash) } catch { $moveRejected = $true }
    Assert-Condition $moveRejected 'before-first-write rename was not denied'
    $beforeWriteSession.Cleanup()
    Assert-Condition (-not [IO.Directory]::Exists($beforeWritePath)) `
        'before-first-write leaf remains'
    Assert-Condition (-not [IO.Directory]::Exists($beforeWriteStash)) `
        'before-first-write rename unexpectedly succeeded'
    Assert-Condition (-not [IO.File]::Exists($beforeWriteMarker)) `
        'before-first-write marker remains'
} finally {
    $beforeWriteSession.Dispose()
    if ([IO.Directory]::Exists($beforeWritePath)) { [IO.Directory]::Delete($beforeWritePath, $true) }
    if ([IO.Directory]::Exists($beforeWriteStash)) { [IO.Directory]::Delete($beforeWriteStash, $true) }
    if ([IO.File]::Exists($beforeWriteMarker)) { [IO.File]::Delete($beforeWriteMarker) }
}

$interruptName = '.capture-ffffffffffffffffffffffffffffffff'
$interruptPath = Join-Path $baseline $interruptName
$interruptStash = Join-Path $baseline 'identity-interruption-stash'
$interruptMarker = Join-Path $baseline ('.' + $interruptName + '.faultloom-owned-v1')
$interruptOutside = Join-Path $baseline 'identity-interruption-outside'
$interruptSentinel = Join-Path $interruptOutside 'sentinel.bin'
$interruptSentinelBytes = [byte[]](9, 8, 7, 6)
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = 'powershell.exe'
$start.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
    $MyInvocation.MyCommand.Path + '" -RepositoryRoot "' + $repository +
    '" -InterruptionChild -InterruptionName ' + $interruptName
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$child = [Diagnostics.Process]::new()
$child.StartInfo = $start
try {
    Assert-Condition $child.Start() 'interruption child did not start'
    $ready = $false
    for ($lineIndex = 0; -not $ready -and $lineIndex -lt 3; ++$lineIndex) {
        $ready = $child.StandardOutput.ReadLine() -ceq 'INTERRUPTION_READY'
    }
    Assert-Condition $ready 'interruption child did not become ready'
    [IO.Directory]::CreateDirectory($interruptOutside) | Out-Null
    [IO.File]::WriteAllBytes($interruptSentinel, $interruptSentinelBytes)
    $moveRejected = $false
    try { [IO.Directory]::Move($interruptPath, $interruptStash) } catch { $moveRejected = $true }
    Assert-Condition $moveRejected 'forced-interruption live rename was not denied'
    $child.Kill()
    Assert-Condition $child.WaitForExit(3000) 'interruption child did not terminate'
    Assert-Bytes ([IO.File]::ReadAllBytes($interruptMarker)) $markerBytes `
        'forced-interruption marker changed'
    $interruptInfo = Get-Item -LiteralPath $interruptPath -Force
    Assert-Condition (($interruptInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) `
        'forced-interruption leaf became a reparse point'
    $interruptMembers = @([IO.Directory]::GetFileSystemEntries($interruptPath))
    Assert-Condition ($interruptMembers.Count -eq 1 -and
        (Split-Path -Leaf $interruptMembers[0]) -ceq 'host.json') `
        'forced-interruption leaf contains foreign members'
    Assert-Bytes ([IO.File]::ReadAllBytes($interruptSentinel)) $interruptSentinelBytes `
        'forced interruption changed the outside sentinel'
} finally {
    if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() }
    $child.Dispose()
    if ([IO.Directory]::Exists($interruptPath)) { [IO.Directory]::Delete($interruptPath, $true) }
    if ([IO.Directory]::Exists($interruptStash)) { [IO.Directory]::Delete($interruptStash, $true) }
    if ([IO.File]::Exists($interruptMarker)) { [IO.File]::Delete($interruptMarker) }
    if ([IO.Directory]::Exists($interruptOutside)) { [IO.Directory]::Delete($interruptOutside, $true) }
}

$cleanupName = '.capture-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
$cleanupPath = Join-Path $baseline $cleanupName
$cleanupStash = Join-Path $baseline 'identity-cleanup-stash'
$cleanupTarget = Join-Path $baseline 'identity-cleanup-target'
$cleanupMarker = Join-Path $baseline ('.' + $cleanupName + '.faultloom-owned-v1')
$cleanupTargetBytes = [byte[]](7, 8, 9)
$cleanupSession = [FaultLoom.Capture.CaptureLeafSession]::Create($baseline, $cleanupName, $markerBytes)
try {
    $cleanupSession.WriteMember('host.json', [byte[]](1))
    $cleanupSession.Validate($false)
    [IO.Directory]::CreateDirectory($cleanupTarget) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $cleanupTarget 'host.json'), $cleanupTargetBytes)
    $moveRejected = $false
    try { [IO.Directory]::Move($cleanupPath, $cleanupStash) } catch { $moveRejected = $true }
    Assert-Condition $moveRejected 'pre-cleanup rename was not denied'
    $cleanupSession.Cleanup()
    Assert-Bytes ([IO.File]::ReadAllBytes((Join-Path $cleanupTarget 'host.json'))) $cleanupTargetBytes 'cleanup changed the outside sentinel'
    Assert-Condition (-not [IO.Directory]::Exists($cleanupPath)) 'retained original cleanup leaf remains'
    Assert-Condition (-not [IO.Directory]::Exists($cleanupStash)) 'cleanup rename unexpectedly succeeded'
    Assert-Condition (-not [IO.File]::Exists($cleanupMarker)) 'temporary cleanup marker remains'
} finally {
    $cleanupSession.Dispose()
    if ([IO.Directory]::Exists($cleanupPath)) { [IO.Directory]::Delete($cleanupPath, $true) }
    if ([IO.Directory]::Exists($cleanupStash)) { [IO.Directory]::Delete($cleanupStash, $true) }
    if ([IO.Directory]::Exists($cleanupTarget)) { [IO.Directory]::Delete($cleanupTarget, $true) }
    if ([IO.File]::Exists($cleanupMarker)) { [IO.File]::Delete($cleanupMarker) }
}

$publishName = '.capture-cccccccccccccccccccccccccccccccc'
$publishPath = Join-Path $baseline $publishName
$publishStash = Join-Path $baseline 'identity-publish-stash'
$publishTarget = Join-Path $baseline 'identity-publish-target'
$publishedName = 'identity-safe-publish'
$publishedPath = Join-Path $baseline $publishedName
$publishMarker = Join-Path $baseline ('.' + $publishName + '.faultloom-owned-v1')
$publishedMarker = Join-Path $baseline ('.' + $publishedName + '.faultloom-owned-v1')
$publishTargetBytes = [byte[]](6, 6, 6)
$publishSession = [FaultLoom.Capture.CaptureLeafSession]::Create($baseline, $publishName, $markerBytes)
try {
    $publishSession.WriteMember('host.json', [byte[]](1))
    $publishSession.WriteMember('services.json', [byte[]](2))
    $publishSession.WriteMember('baseline.sha256', [byte[]](3))
    $publishSession.Validate($true)
    [IO.Directory]::CreateDirectory($publishTarget) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $publishTarget 'host.json'), $publishTargetBytes)
    $moveRejected = $false
    try { [IO.Directory]::Move($publishPath, $publishStash) } catch { $moveRejected = $true }
    Assert-Condition $moveRejected 'mid-publish rename was not denied'
    $publishSession.Publish($publishedName, $markerBytes)
    Assert-Bytes ([IO.File]::ReadAllBytes((Join-Path $publishTarget 'host.json'))) $publishTargetBytes 'publication changed the outside sentinel'
    Assert-Bytes ([IO.File]::ReadAllBytes((Join-Path $publishedPath 'host.json'))) ([byte[]](1)) 'publication did not move retained original leaf'
    Assert-Condition (-not [IO.Directory]::Exists($publishPath)) 'temporary publish leaf remains'
    Assert-Condition (-not [IO.Directory]::Exists($publishStash)) 'publish rename unexpectedly succeeded'
    Assert-Condition (-not [IO.File]::Exists($publishMarker)) 'temporary publish marker remains'
    Assert-Bytes ([IO.File]::ReadAllBytes($publishedMarker)) $markerBytes 'published marker is malformed'
} finally {
    $publishSession.Dispose()
    if ([IO.Directory]::Exists($publishPath)) { [IO.Directory]::Delete($publishPath, $true) }
    if ([IO.Directory]::Exists($publishStash)) { [IO.Directory]::Delete($publishStash, $true) }
    if ([IO.Directory]::Exists($publishTarget)) { [IO.Directory]::Delete($publishTarget, $true) }
    if ([IO.Directory]::Exists($publishedPath)) {
        foreach ($file in [IO.Directory]::GetFiles($publishedPath)) { [IO.File]::Delete($file) }
        [IO.Directory]::Delete($publishedPath)
    }
    if ([IO.File]::Exists($publishMarker)) { [IO.File]::Delete($publishMarker) }
    if ([IO.File]::Exists($publishedMarker)) { [IO.File]::Delete($publishedMarker) }
}

[Console]::Out.WriteLine('CAPTURE_LEAF_IDENTITY_TEST_OK')
