[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [switch]$AttackChild,
    [switch]$TransactionProbeChild,
    [string]$Target,
    [string]$Stash,
    [string]$Junction,
    [string]$Replacement,
    [string]$OwnerMarker,
    [string]$TransactionRepository,
    [string]$Ready,
    [string]$Stop,
    [string]$Cycles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($TransactionProbeChild) {
    $markerBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        "FaultLoom Windows Authority MVP v1`n")
    $methods = [IO.File]::ReadAllText((Join-Path $RepositoryRoot `
        'native\windows_authority\tools\capture_native_methods.cs'))
    $sessionSource = [IO.File]::ReadAllText((Join-Path $RepositoryRoot `
        'native\windows_authority\tools\owned_leaf_session.cs'))
    Add-Type -TypeDefinition ("#define FAULTLOOM_TRANSACTION_TEST_HOOK`n" +
        $methods + "`n" + $sessionSource)
    $originalSentinel = Join-Path $Target 'original.bin'
    $replacementSentinel = Join-Path $Replacement 'replacement.bin'
    $originalNames = (@([IO.Directory]::GetFileSystemEntries($Target) |
        ForEach-Object { Split-Path -Leaf $_ } | Sort-Object) -join "`n")
    $replacementNames = (@([IO.Directory]::GetFileSystemEntries($Replacement) |
        ForEach-Object { Split-Path -Leaf $_ } | Sort-Object) -join "`n")
    $originalBytes = [IO.File]::ReadAllBytes($originalSentinel)
    $replacementBytes = [IO.File]::ReadAllBytes($replacementSentinel)
    $markerBefore = [IO.File]::ReadAllBytes($OwnerMarker)
    $script:probeMoved = $false
    [FaultLoom.Capture.OwnedParentSession]::TestAfterPublicationParentOpened = [Action]{
        try {
            [IO.Directory]::Move($Target, $Stash)
            $script:probeMoved = $true
            [IO.Directory]::Move($Replacement, $Target)
        } catch { }
    }
    $retained = $null
    try {
        $retained = [FaultLoom.Capture.OwnedParentSession]::OpenAndVerify(
            $TransactionRepository, $Target, $markerBytes)
        $retained.Validate()
        $temporaryName = '.package-' + [Guid]::NewGuid().ToString('N')
        [FaultLoom.Capture.OwnedLeafSession]::TestAfterTemporaryDirectoryCreated = [Action]{
            throw [IO.InvalidDataException]::new('forced post-create validation failure')
        }
        $creationFailed = $false
        try {
            [FaultLoom.Capture.OwnedLeafSession]::Create($retained,
                $temporaryName, $markerBytes, [string[]]@('probe.bin'), 1024, 1024) |
                Out-Null
        } catch {
            $creationFailed = $true
        }
        if (-not $creationFailed) { throw 'forced temporary validation failure succeeded' }
        if ([IO.Directory]::Exists((Join-Path $Target $temporaryName)) -or
            [IO.File]::Exists((Join-Path $Target `
                ('.' + $temporaryName + '.faultloom-owned-v1')))) {
            throw 'post-create validation failure left a temporary identity'
        }
    } finally {
        if ($null -ne $retained) { $retained.Dispose() }
        if ($script:probeMoved) {
            if ([IO.Directory]::Exists($Target) -and
                -not [IO.Directory]::Exists($Replacement)) {
                [IO.Directory]::Move($Target, $Replacement)
            }
            if ([IO.Directory]::Exists($Stash) -and
                -not [IO.Directory]::Exists($Target)) {
                [IO.Directory]::Move($Stash, $Target)
            }
        }
    }
    if ($script:probeMoved) { throw 'transaction allowed publication-parent replacement' }
    if ([IO.Directory]::Exists($Stash)) { throw 'transaction left an original stash' }
    if ((@([IO.Directory]::GetFileSystemEntries($Target) |
            ForEach-Object { Split-Path -Leaf $_ } | Sort-Object) -join "`n") -cne
        $originalNames) { throw 'transaction changed the original identity' }
    if ((@([IO.Directory]::GetFileSystemEntries($Replacement) |
            ForEach-Object { Split-Path -Leaf $_ } | Sort-Object) -join "`n") -cne
        $replacementNames) { throw 'transaction changed the replacement identity' }
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($originalSentinel)) -cne
        [Convert]::ToBase64String($originalBytes)) {
        throw 'transaction changed the original sentinel'
    }
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($replacementSentinel)) -cne
        [Convert]::ToBase64String($replacementBytes)) {
        throw 'transaction changed the replacement sentinel'
    }
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($OwnerMarker)) -cne
        [Convert]::ToBase64String($markerBefore)) {
        throw 'transaction changed the owner marker'
    }
    [Console]::Out.WriteLine('TRANSACTION_SWAP_PROBE_OK')
    exit 0
}

function Restore-AttackTarget {
    if (-not [IO.Directory]::Exists($Stash)) { return }
    if ([IO.Directory]::Exists($Target) -and -not [IO.Directory]::Exists($Junction)) {
        try { [IO.Directory]::Move($Target, $Junction) } catch { }
    }
    if (-not [IO.Directory]::Exists($Target) -and [IO.Directory]::Exists($Stash)) {
        try { [IO.Directory]::Move($Stash, $Target) } catch { }
    }
}

if ($AttackChild) {
    $count = 0
    [IO.File]::WriteAllText($Ready, 'ready')
    try {
        while (-not [IO.File]::Exists($Stop)) {
            try {
                if ([IO.Directory]::Exists($Target) -and
                    [IO.Directory]::Exists($Junction) -and
                    -not [IO.Directory]::Exists($Stash)) {
                    [IO.Directory]::Move($Target, $Stash)
                    [IO.Directory]::Move($Junction, $Target)
                    [Threading.Thread]::Sleep(2)
                    [IO.Directory]::Move($Target, $Junction)
                    [IO.Directory]::Move($Stash, $Target)
                    ++$count
                }
            } catch {
                Restore-AttackTarget
            }
        }
    } finally {
        Restore-AttackTarget
        [IO.File]::WriteAllText($Cycles, $count.ToString())
    }
    exit 0
}

function Assert-Condition([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Bytes([byte[]]$Actual, [byte[]]$Expected, [string]$Message) {
    Assert-Condition ($Actual.Length -eq $Expected.Length) $Message
    for ($index = 0; $index -lt $Actual.Length; ++$index) {
        Assert-Condition ($Actual[$index] -eq $Expected[$index]) $Message
    }
}

function New-IsolatedRepository([string]$Path, [bool]$WithOut) {
    $source = Join-Path $Path 'native\windows_authority'
    [IO.Directory]::CreateDirectory($source) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $source '.faultloom-source-root-v1'), $script:markerBytes)
    if ($WithOut) { [IO.Directory]::CreateDirectory((Join-Path $Path 'out')) | Out-Null }
}

function Invoke-ExpectedFailure([string[]]$Arguments, [string]$Message) {
    $failed = $false
    try { & $script:verify @Arguments | Out-Null } catch { $failed = $true }
    Assert-Condition $failed $Message
}

function New-Junction([string]$Path, [string]$Destination) {
    & cmd.exe /d /c mklink /J $Path $Destination | Out-Null
    Assert-Condition ($LASTEXITCODE -eq 0 -and [IO.Directory]::Exists($Path)) `
        'could not create junction fixture'
}

function Remove-Junction([string]$Path) {
    if (-not [IO.Directory]::Exists($Path)) { return }
    & cmd.exe /d /c rmdir $Path
    Assert-Condition ($LASTEXITCODE -eq 0) 'could not remove junction fixture'
}

function Start-Attacker([string]$TargetPath, [string]$FixturePath, [string]$OutsidePath) {
    $nonce = [Guid]::NewGuid().ToString('N')
    $state = [pscustomobject]@{
        Target = $TargetPath
        Stash = Join-Path $FixturePath ('stash-' + $nonce)
        Junction = Join-Path $FixturePath ('junction-' + $nonce)
        Ready = Join-Path $FixturePath ('ready-' + $nonce)
        Stop = Join-Path $FixturePath ('stop-' + $nonce)
        Cycles = Join-Path $FixturePath ('cycles-' + $nonce)
        Stdout = Join-Path $FixturePath ('stdout-' + $nonce)
        Stderr = Join-Path $FixturePath ('stderr-' + $nonce)
        Process = $null
    }
    New-Junction $state.Junction $OutsidePath
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath, '-RepositoryRoot', $script:repository, '-AttackChild',
        '-Target', $state.Target, '-Stash', $state.Stash, '-Junction', $state.Junction,
        '-Ready', $state.Ready, '-Stop', $state.Stop, '-Cycles', $state.Cycles)
    $state.Process = Start-Process powershell.exe -ArgumentList $arguments -WindowStyle Hidden `
        -RedirectStandardOutput $state.Stdout -RedirectStandardError $state.Stderr -PassThru
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while (-not [IO.File]::Exists($state.Ready) -and $watch.ElapsedMilliseconds -lt 5000) {
        Start-Sleep -Milliseconds 10
    }
    Assert-Condition ([IO.File]::Exists($state.Ready)) 'replacement attacker did not become ready'
    return $state
}

function Stop-Attacker($State) {
    [IO.File]::WriteAllText($State.Stop, 'stop')
    $failure = ''
    if (-not $State.Process.WaitForExit(10000)) {
        $State.Process.Kill()
        $State.Process.WaitForExit()
        $failure = 'replacement attacker did not stop'
    } else {
        $State.Process.WaitForExit()
    }
    $State.Process.Refresh()
    $details = if ([IO.File]::Exists($State.Stderr)) {
        [IO.File]::ReadAllText($State.Stderr)
    } else { '' }
    $childOutput = if ([IO.File]::Exists($State.Stdout)) {
        [IO.File]::ReadAllText($State.Stdout)
    } else { '' }
    $exitCode = $State.Process.ExitCode
    if ($null -ne $exitCode -and $exitCode -ne 0) {
        $failure = "replacement attacker failed ($exitCode): $details $childOutput"
    }
    $restoreWatch = [Diagnostics.Stopwatch]::StartNew()
    $restoreError = ''
    while ([IO.Directory]::Exists($State.Stash) -and $restoreWatch.ElapsedMilliseconds -lt 5000) {
        if ([IO.Directory]::Exists($State.Target) -and
            -not [IO.Directory]::Exists($State.Junction)) {
            try { [IO.Directory]::Move($State.Target, $State.Junction) } catch {
                $restoreError = $_.Exception.Message
            }
        }
        if (-not [IO.Directory]::Exists($State.Target)) {
            try { [IO.Directory]::Move($State.Stash, $State.Target) } catch {
                $restoreError = $_.Exception.Message
            }
        }
        if ([IO.Directory]::Exists($State.Stash)) { Start-Sleep -Milliseconds 10 }
    }
    if ([IO.Directory]::Exists($State.Junction)) { Remove-Junction $State.Junction }
    if (-not [IO.Directory]::Exists($State.Target)) { $failure = 'replacement target was not restored' }
    if ([IO.Directory]::Exists($State.Stash)) {
        $targetFacts = if ([IO.Directory]::Exists($State.Target)) {
            (Get-Item -LiteralPath $State.Target -Force).Attributes.ToString()
        } else { 'missing' }
        $junctionFacts = if ([IO.Directory]::Exists($State.Junction)) {
            (Get-Item -LiteralPath $State.Junction -Force).Attributes.ToString()
        } else { 'missing' }
        $failure = "replacement stash remains; target=$targetFacts junction=$junctionFacts error=$restoreError"
    }
    if (-not [IO.File]::Exists($State.Cycles) -or
        [int][IO.File]::ReadAllText($State.Cycles) -le 0) {
        $failure = 'replacement attacker completed no junction cycles'
    }
    Assert-Condition ([string]::IsNullOrEmpty($failure)) $failure
}

function Assert-OutsideUntouched([string]$Outside, [byte[]]$Sentinel) {
    $entries = @([IO.Directory]::GetFileSystemEntries($Outside))
    Assert-Condition ($entries.Count -eq 1) 'outside target gained a member'
    Assert-Bytes ([IO.File]::ReadAllBytes((Join-Path $Outside 'sentinel.bin'))) $Sentinel `
        'outside sentinel changed'
}

function Invoke-TransactionSwapProbe([string]$TransactionRepository, [string]$Parent,
        [string]$Replacement,
        [string]$Stash, [string]$OwnerMarker, [string]$Label) {
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & powershell.exe -NoLogo -NoProfile -NonInteractive `
            -ExecutionPolicy Bypass -File $PSCommandPath -RepositoryRoot $script:repository `
            -TransactionProbeChild -Target $Parent -Replacement $Replacement `
            -Stash $Stash -OwnerMarker $OwnerMarker `
            -TransactionRepository $TransactionRepository 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldPreference
    }
    Assert-Condition ($exitCode -eq 0) `
        "$Label authoritative transaction swap probe failed: $($output -join ' ')"
    Assert-Condition (($output -join "`n").Contains('TRANSACTION_SWAP_PROBE_OK')) `
        "$Label authoritative transaction probe emitted no success evidence"
}

$repository = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\')
$verify = Join-Path $repository 'native\windows_authority\tools\verify-roots.ps1'
$generated = Join-Path $repository 'out\windows_authority'
$build = Join-Path $generated 'build'
$markerBytes = [Text.UTF8Encoding]::new($false).GetBytes("FaultLoom Windows Authority MVP v1`n")

& $verify -RepositoryRoot $repository -Mode Configure -BuildDir $build | Out-Null
Assert-Condition (($null -ne ('FaultLoom.Roots.OwnedCreation' -as [type]))) `
    'retained handle-relative creator is missing'
if (-not ('FaultLoom.Capture.OwnedParentSession' -as [type])) {
    $methods = [IO.File]::ReadAllText((Join-Path $repository `
        'native\windows_authority\tools\capture_native_methods.cs'))
    $sessionSource = [IO.File]::ReadAllText((Join-Path $repository `
        'native\windows_authority\tools\owned_leaf_session.cs'))
    Add-Type -TypeDefinition ($methods + "`n" + $sessionSource)
}
$fixtureName = 'root-creation-fixtures-' + [Guid]::NewGuid().ToString('N')
$fixture = Join-Path $generated $fixtureName
$fixtureMarker = Join-Path $generated ('.' + $fixtureName + '.faultloom-owned-v1')
[FaultLoom.Roots.OwnedCreation]::CreateOwnedLeaf(
    $repository, $generated, $fixtureName, $markerBytes)
$activeAttacker = $null

try {
    $missingSmoke = Join-Path $fixture 'missing-smoke'
    New-IsolatedRepository $missingSmoke $false
    Invoke-ExpectedFailure @('-RepositoryRoot', $missingSmoke, '-Mode', 'Smoke',
        '-BuildDir', (Join-Path $missingSmoke 'out\windows_authority\build'),
        '-EvidenceDir', (Join-Path $missingSmoke 'out\windows_authority\smoke-evidence\run')) `
        'Smoke created a missing generated root'
    Assert-Condition (-not [IO.Directory]::Exists((Join-Path $missingSmoke 'out'))) `
        'Smoke wrote before a retained generated-root session'

    $missingPackage = Join-Path $fixture 'missing-package'
    New-IsolatedRepository $missingPackage $false
    Invoke-ExpectedFailure @('-RepositoryRoot', $missingPackage, '-Mode', 'Package',
        '-BuildDir', (Join-Path $missingPackage 'out\windows_authority\build'),
        '-OutputDir', (Join-Path $missingPackage 'out\windows_authority\package\run')) `
        'Package created a missing generated root'
    Assert-Condition (-not [IO.Directory]::Exists((Join-Path $missingPackage 'out'))) `
        'Package wrote before a retained generated-root session'

    $configureRepo = Join-Path $fixture 'configure-first-run'
    New-IsolatedRepository $configureRepo $false
    & $verify -RepositoryRoot $configureRepo -Mode Configure `
        -BuildDir (Join-Path $configureRepo 'out\windows_authority\build') | Out-Null
    Assert-Bytes ([IO.File]::ReadAllBytes((Join-Path $configureRepo `
        'out\windows_authority\.faultloom-generated-root-v1'))) $markerBytes `
        'Configure generated-root marker is malformed'
    Assert-Bytes ([IO.File]::ReadAllBytes((Join-Path $configureRepo `
        'out\windows_authority\.build.faultloom-owned-v1'))) $markerBytes `
        'Configure build marker is malformed'

    $originalSentinel = [byte[]](11, 22, 33, 44, 55)
    $replacementSentinel = [byte[]](55, 44, 33, 22, 11)
    $retainedPackageRoot = Join-Path $configureRepo 'out\windows_authority\package'
    $packageReplacement = Join-Path $configureRepo 'package-parent-replacement'
    $packageStash = Join-Path $configureRepo 'package-parent-stash'
    [IO.Directory]::CreateDirectory($packageReplacement) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $packageReplacement 'replacement.bin'),
        $replacementSentinel)
    $firstRunSession = & $verify -RepositoryRoot $configureRepo -Mode Package `
        -BuildDir (Join-Path $configureRepo 'out\windows_authority\build') `
        -OutputDir (Join-Path $retainedPackageRoot 'first-run-probe') `
        -RetainMutationParent
    try {
        $firstRunSession.Validate()
    } finally {
        $firstRunSession.Dispose()
    }
    [IO.File]::WriteAllBytes((Join-Path $retainedPackageRoot 'original.bin'),
        $originalSentinel)
    Invoke-TransactionSwapProbe $configureRepo $retainedPackageRoot $packageReplacement `
        $packageStash `
        (Join-Path $configureRepo 'out\windows_authority\.package.faultloom-owned-v1') `
        'Package'

    $retainedSmokeRoot = Join-Path $configureRepo 'out\windows_authority\smoke-evidence'
    $smokeReplacement = Join-Path $configureRepo 'smoke-parent-replacement'
    $smokeStash = Join-Path $configureRepo 'smoke-parent-stash'
    [IO.Directory]::CreateDirectory($smokeReplacement) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $smokeReplacement 'replacement.bin'),
        $replacementSentinel)
    [FaultLoom.Roots.OwnedCreation]::CreateOwnedLeaf(
        $configureRepo, (Join-Path $configureRepo 'out\windows_authority'),
        'smoke-evidence', $markerBytes)
    [IO.File]::WriteAllBytes((Join-Path $retainedSmokeRoot 'original.bin'),
        $originalSentinel)
    Invoke-TransactionSwapProbe $configureRepo $retainedSmokeRoot $smokeReplacement `
        $smokeStash `
        (Join-Path $configureRepo `
            'out\windows_authority\.smoke-evidence.faultloom-owned-v1') 'Smoke'

    $sentinel = [byte[]](0, 1, 2, 127, 128, 253, 254, 255)
    $rootRaceRepo = Join-Path $fixture 'root-race'
    New-IsolatedRepository $rootRaceRepo $true
    $rootOutside = Join-Path $fixture 'root-race-outside'
    [IO.Directory]::CreateDirectory($rootOutside) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $rootOutside 'sentinel.bin'), $sentinel)
    $rootTarget = Join-Path $rootRaceRepo 'out'
    $rootAttacker = Start-Attacker $rootTarget $fixture $rootOutside
    $activeAttacker = $rootAttacker
    $rootCreated = $false
    try {
        for ($attempt = 0; $attempt -lt 200 -and -not $rootCreated; ++$attempt) {
            try {
                [FaultLoom.Roots.OwnedCreation]::CreateRoot($rootRaceRepo,
                    $rootTarget,
                    (Join-Path $rootTarget 'windows_authority'),
                    '.faultloom-generated-root-v1', [byte[]]::new(2MB))
                $rootCreated = $true
            } catch { Start-Sleep -Milliseconds 1 }
        }
    } finally {
        Stop-Attacker $rootAttacker
        $activeAttacker = $null
    }
    Assert-Condition $rootCreated 'repo-to-generated creation never acquired its retained parent'
    Assert-OutsideUntouched $rootOutside $sentinel

    $leafRaceRepo = Join-Path $fixture 'leaf-race'
    New-IsolatedRepository $leafRaceRepo $false
    & $verify -RepositoryRoot $leafRaceRepo -Mode Configure `
        -BuildDir (Join-Path $leafRaceRepo 'out\windows_authority\build') | Out-Null
    $leafGenerated = Join-Path $leafRaceRepo 'out\windows_authority'
    $leafOutside = Join-Path $fixture 'leaf-race-outside'
    [IO.Directory]::CreateDirectory($leafOutside) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $leafOutside 'sentinel.bin'), $sentinel)
    $leafAttacker = Start-Attacker $leafGenerated $fixture $leafOutside
    $activeAttacker = $leafAttacker
    $createdLeaves = New-Object 'Collections.Generic.List[string]'
    try {
        foreach ($leafName in @('package', 'smoke-evidence')) {
            $created = $false
            for ($attempt = 0; $attempt -lt 200 -and -not $created; ++$attempt) {
                try {
                    [FaultLoom.Roots.OwnedCreation]::CreateOwnedLeaf(
                        $leafRaceRepo, $leafGenerated, $leafName, [byte[]]::new(2MB))
                    $created = $true
                    $createdLeaves.Add($leafName)
                } catch { Start-Sleep -Milliseconds 1 }
            }
            Assert-Condition $created "generated-to-$leafName creation never acquired its retained parent"
        }

        for ($attempt = 0; $attempt -lt 40; ++$attempt) {
            try {
                [FaultLoom.Roots.OwnedCreation]::CreateRoot($leafRaceRepo,
                    $leafGenerated,
                    (Join-Path $leafGenerated ('interrupted-' + $attempt)),
                    'bad\marker', $markerBytes)
                throw 'forced marker failure unexpectedly succeeded'
            } catch { }
        }
    } finally {
        Stop-Attacker $leafAttacker
        $activeAttacker = $null
    }
    Assert-OutsideUntouched $leafOutside $sentinel
    for ($attempt = 0; $attempt -lt 40; ++$attempt) {
        Assert-Condition (-not [IO.Directory]::Exists(
            (Join-Path $leafGenerated ('interrupted-' + $attempt)))) `
            'forced failure left a created directory identity'
    }
} finally {
    if ($null -ne $activeAttacker) {
        try { Stop-Attacker $activeAttacker } catch {
            if (-not $activeAttacker.Process.HasExited) { $activeAttacker.Process.Kill() }
        }
    }
    if ([IO.Directory]::Exists($fixture)) { [IO.Directory]::Delete($fixture, $true) }
    if ([IO.File]::Exists($fixtureMarker)) { [IO.File]::Delete($fixtureMarker) }
}

[Console]::Out.WriteLine('ROOT_CREATION_IDENTITY_OK')
