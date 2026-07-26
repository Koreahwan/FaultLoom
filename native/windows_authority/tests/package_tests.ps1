[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$BuildDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$markerBytes = $utf8.GetBytes("FaultLoom Windows Authority MVP v1`n")
$repository = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\')
$packageRoot = Join-Path $repository 'out\windows_authority\package'
$packageScript = Join-Path $repository 'native\windows_authority\tools\package.ps1'
$verifyScript = Join-Path $repository 'native\windows_authority\tools\verify-package.ps1'
$contractFixtureRoot = Join-Path $packageRoot 'package-contract-fixtures'
$expectedNames = @('faultloom_broker.exe', 'faultloom_ctl.exe', 'faultloom_reviewer.exe',
    'README.md', 'INSTALL-GATE.md', 'package-manifest.json', 'SHA256SUMS.txt')

function Assert-Condition([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Get-Sha256([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try {
        return (($algorithm.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $stream.Dispose()
        $algorithm.Dispose()
    }
}

function Invoke-Isolated([string]$Script, [string[]]$Arguments) {
    $preference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
            -File $Script @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $preference
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join "`n") }
}

function Invoke-ConstrainedExecutable([string]$Executable, [string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.WorkingDirectory = Split-Path -Parent $Executable
    $start.EnvironmentVariables.Clear()
    $start.EnvironmentVariables['SystemRoot'] = $env:SystemRoot
    $start.EnvironmentVariables['WINDIR'] = $env:SystemRoot
    $start.EnvironmentVariables['PATH'] = Join-Path $env:SystemRoot 'System32'
    $start.Arguments = $Arguments -join ' '
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $watch = [Diagnostics.Stopwatch]::StartNew()
    Assert-Condition $process.Start() "could not start $Executable"
    if (-not $process.WaitForExit(11000)) {
        $process.Kill()
        throw "local command exceeded its deadline: $($Arguments -join ' ')"
    }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $watch.Stop()
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        Output = $stdout
        Error = $stderr
        ElapsedMilliseconds = $watch.ElapsedMilliseconds
    }
}

function Get-PackageSnapshot([string]$Path) {
    $items = @([IO.Directory]::GetFileSystemEntries($Path) | Sort-Object)
    $records = foreach ($item in $items) {
        $info = Get-Item -LiteralPath $item -Force
        if ($info -is [IO.FileInfo]) {
            "F|$($info.Name)|$($info.Length)|$($info.LastWriteTimeUtc.Ticks)|$(Get-Sha256 $item)"
        } else {
            "D|$($info.Name)|$($info.Attributes)|$($info.LastWriteTimeUtc.Ticks)"
        }
    }
    return $records -join "`n"
}

function Get-RecursiveSnapshot([string]$Path) {
    $root = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $records = foreach ($item in @(Get-ChildItem -LiteralPath $root -Force -Recurse |
            Sort-Object FullName)) {
        $relative = $item.FullName.Substring($root.Length + 1)
        if ($item -is [IO.FileInfo]) {
            "F|$relative|$($item.Length)|$($item.LastWriteTimeUtc.Ticks)|$(Get-Sha256 $item.FullName)"
        } else {
            "D|$relative|$($item.Attributes)"
        }
    }
    return $records -join "`n"
}

function Assert-CleanRootVerifierFailsReadOnly([string]$Label, [bool]$OutsideInput) {
    $nonce = [Guid]::NewGuid().ToString('N')
    $fixtureRoot = Join-Path $contractFixtureRoot ('verifier-clean-' + $Label + '-' + $nonce)
    $foreignRoot = Join-Path $contractFixtureRoot ('verifier-foreign-' + $Label + '-' + $nonce)
    try {
        $fixtureTools = Join-Path $fixtureRoot 'native\windows_authority\tools'
        $fixtureSource = Split-Path -Parent $fixtureTools
        [IO.Directory]::CreateDirectory($fixtureTools) | Out-Null
        [IO.Directory]::CreateDirectory($foreignRoot) | Out-Null
        [IO.File]::Copy($verifyScript, (Join-Path $fixtureTools 'verify-package.ps1'))
        [IO.File]::Copy((Join-Path $repository 'native\windows_authority\tools\verify-roots.ps1'),
            (Join-Path $fixtureTools 'verify-roots.ps1'))
        $sourceMarker = Join-Path $repository `
            'native\windows_authority\.faultloom-source-root-v1'
        [IO.File]::Copy($sourceMarker, (Join-Path $fixtureSource '.faultloom-source-root-v1'))
        [IO.File]::WriteAllBytes((Join-Path $foreignRoot 'sentinel.bin'),
            [byte[]](0, 1, 2, 127, 128, 254, 255))

        $fixtureBefore = Get-RecursiveSnapshot $fixtureRoot
        $foreignBefore = Get-RecursiveSnapshot $foreignRoot
        $fixtureVerifier = Join-Path $fixtureTools 'verify-package.ps1'
        if ($OutsideInput) {
            $packageInput = $foreignRoot
        } else {
            $packageInput = Join-Path $fixtureRoot 'out\windows_authority\package\missing'
        }
        $result = Invoke-Isolated $fixtureVerifier @('-PackageDir', $packageInput)
        Assert-Condition ($result.ExitCode -ne 0) "$Label clean-root verifier input was accepted"

        $fixtureGenerated = Join-Path $fixtureRoot 'out\windows_authority'
        $fixtureMarker = Join-Path $fixtureGenerated '.faultloom-generated-root-v1'
        Assert-Condition (-not [IO.Directory]::Exists((Join-Path $fixtureRoot 'out'))) `
            "$Label clean-root verifier created an out path"
        Assert-Condition (-not [IO.File]::Exists($fixtureMarker)) `
            "$Label clean-root verifier wrote the generated-root marker"
        $fixtureAfter = Get-RecursiveSnapshot $fixtureRoot
        $foreignAfter = Get-RecursiveSnapshot $foreignRoot
        Assert-Condition ($fixtureAfter -ceq $fixtureBefore) `
            "$Label clean-root verifier changed its isolated repository"
        Assert-Condition ($foreignAfter -ceq $foreignBefore) `
            "$Label clean-root verifier changed the foreign path"
    } finally {
        if ([IO.Directory]::Exists($fixtureRoot)) { [IO.Directory]::Delete($fixtureRoot, $true) }
        if ([IO.Directory]::Exists($foreignRoot)) { [IO.Directory]::Delete($foreignRoot, $true) }
    }
}

function Assert-VerifyFailsReadOnly([string]$Path, [string]$Label) {
    $before = Get-PackageSnapshot $Path
    $result = Invoke-Isolated $verifyScript @('-PackageDir', $Path)
    $after = Get-PackageSnapshot $Path
    Assert-Condition ($result.ExitCode -ne 0) "$Label was accepted"
    Assert-Condition ($before -ceq $after) "$Label caused verifier writes"
}

function Assert-VerifyPasses([string]$Path) {
    $result = Invoke-Isolated $verifyScript @('-PackageDir', $Path)
    Assert-Condition ($result.ExitCode -eq 0) "valid package rejected: $($result.Output)"
    Assert-Condition ($result.Output.EndsWith('PACKAGE_VERIFY_OK')) 'verifier success record missing'
}

function Remove-OwnedPackage([string]$Path) {
    $marker = Join-Path $packageRoot ('.' + (Split-Path -Leaf $Path) + '.faultloom-owned-v1')
    if (-not [IO.Directory]::Exists($Path) -and -not [IO.File]::Exists($marker)) { return }
    Assert-Condition ([IO.Directory]::Exists($Path) -and [IO.File]::Exists($marker)) `
        'owned package cleanup pair is incomplete'
    $actual = [IO.File]::ReadAllBytes($marker)
    Assert-Condition ($actual.Length -eq $markerBytes.Length) 'owned package marker length changed'
    for ($index = 0; $index -lt $actual.Length; ++$index) {
        Assert-Condition ($actual[$index] -eq $markerBytes[$index]) 'owned package marker changed'
    }
    [IO.Directory]::Delete($Path, $true)
    [IO.File]::Delete($marker)
}

function New-OwnedFixtureRoot([string]$Path) {
    Remove-OwnedPackage $Path
    $marker = Join-Path $packageRoot ('.' + (Split-Path -Leaf $Path) + '.faultloom-owned-v1')
    [IO.Directory]::CreateDirectory($Path) | Out-Null
    try {
        [IO.File]::WriteAllBytes($marker, $markerBytes)
    } catch {
        [IO.Directory]::Delete($Path)
        throw
    }
}

function Assert-LocalCommands([string]$Package) {
    $names = @([IO.Directory]::GetFileSystemEntries($Package) |
        ForEach-Object { Split-Path -Leaf $_ } | Sort-Object)
    Assert-Condition ($names.Count -eq 7) 'local-command fixture member count is not seven'
    Assert-Condition (($names -join '|') -ceq (($expectedNames | Sort-Object) -join '|')) `
        'local-command fixture members differ'
    $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
    $before = @(& $sc qc BFE 2>&1) -join "`n"
    Assert-Condition ($LASTEXITCODE -eq 0) 'BFE read-only SCM snapshot failed'
    $ctl = [IO.Path]::GetFullPath((Join-Path $Package 'faultloom_ctl.exe'))
    $ping = Invoke-ConstrainedExecutable $ctl @('local', 'ping')
    Assert-Condition ($ping.ExitCode -eq 0 -and $ping.Output -ceq "PONG`r`n" -and
        $ping.Error.Length -eq 0 -and $ping.ElapsedMilliseconds -le 10000) `
        "local ping failed: exit=$($ping.ExitCode) stdout=$($ping.Output) stderr=$($ping.Error)"
    $query = Invoke-ConstrainedExecutable $ctl @('local', 'query-service', '--name', 'BFE')
    $signedStatus = $query.ExitCode -eq 0 -and
        $query.Output -cmatch '^SERVICE_STATUS( [0-9]+){9}\r\n$'
    $signedFailure = $query.ExitCode -eq 7 -and $query.Output -ceq "ACTION_FAILED`r`n"
    Assert-Condition (($signedStatus -or $signedFailure) -and $query.Error.Length -eq 0 -and
        $query.ElapsedMilliseconds -le 10000) `
        "local query failed: exit=$($query.ExitCode) stdout=$($query.Output) stderr=$($query.Error)"
    $after = @(& $sc qc BFE 2>&1) -join "`n"
    Assert-Condition ($LASTEXITCODE -eq 0 -and $after -ceq $before) `
        'local commands changed the allowlisted service configuration'
}

function Test-ByteMutation([string]$Package, [string]$Name, [byte[]]$Bytes,
                           [byte[]]$Original, [string]$Label) {
    $path = Join-Path $Package $Name
    try {
        [IO.File]::WriteAllBytes($path, $Bytes)
        Assert-VerifyFailsReadOnly $Package $Label
    } finally {
        [IO.File]::WriteAllBytes($path, $Original)
    }
}

Assert-Condition ([IO.File]::Exists($packageScript)) 'package.ps1 is missing'
Assert-Condition ([IO.File]::Exists($verifyScript)) 'verify-package.ps1 is missing'
$packageA = Join-Path $packageRoot 'todo6-test-a'
$packageB = Join-Path $packageRoot 'todo6-test-b'
try {
    New-OwnedFixtureRoot $contractFixtureRoot
    Remove-OwnedPackage $packageA
    Remove-OwnedPackage $packageB
    foreach ($package in @($packageA, $packageB)) {
        $result = Invoke-Isolated $packageScript @('-BuildDir', $BuildDir, '-Configuration',
            'Release', '-OutputDir', $package)
        Assert-Condition ($result.ExitCode -eq 0) "package creation failed: $($result.Output)"
        Assert-VerifyPasses $package
    }
    $namesA = @([IO.Directory]::GetFiles($packageA) | ForEach-Object { Split-Path -Leaf $_ } |
        Sort-Object)
    Assert-Condition ($namesA.Count -eq 7) 'package member count is not seven'
    Assert-Condition (($namesA -join '|') -ceq (($expectedNames | Sort-Object) -join '|')) `
        'package member names differ'
    Assert-LocalCommands $packageA
    foreach ($name in $expectedNames) {
        Assert-Condition ((Get-Sha256 (Join-Path $packageA $name)) -ceq
            (Get-Sha256 (Join-Path $packageB $name))) "determinism failed for $name"
    }

    $manifestPath = Join-Path $packageA 'package-manifest.json'
    $checksumPath = Join-Path $packageA 'SHA256SUMS.txt'
    $manifest = [IO.File]::ReadAllBytes($manifestPath)
    $checksums = [IO.File]::ReadAllBytes($checksumPath)
    $manifestText = $utf8.GetString($manifest)
    $checksumText = $utf8.GetString($checksums)
    $fileObjects = @([regex]::Matches($manifestText,
        '\{"filename":"[A-Za-z0-9._-]+","size":[0-9]+,"sha256":"[0-9a-f]{64}"\}'))
    Assert-Condition ($fileObjects.Count -eq 5) 'valid manifest file objects were not recognized'
    $swappedFiles = $manifestText.Replace(
        $fileObjects[0].Value + ',' + $fileObjects[1].Value,
        $fileObjects[1].Value + ',' + $fileObjects[0].Value)
    $manifestCases = @(
        @('manifest BOM', ([byte[]](0xEF, 0xBB, 0xBF) + $manifest)),
        @('manifest CRLF', $utf8.GetBytes($manifestText.Replace("`n", "`r`n"))),
        @('manifest whitespace', $utf8.GetBytes($manifestText.Replace('{"schema', '{ "schema'))),
        @('manifest missing LF', $utf8.GetBytes($manifestText.TrimEnd("`n"))),
        @('manifest extra LF', $utf8.GetBytes($manifestText + "`n")),
        @('duplicate top property', $utf8.GetBytes($manifestText.Replace(
            '"schema_version":1,', '"schema_version":1,"schema_version":1,'))),
        @('unknown top property', $utf8.GetBytes($manifestText.Replace(
            '"schema_version":1,', '"schema_version":1,"unknown":0,'))),
        @('misordered top properties', $utf8.GetBytes($manifestText.Replace(
            '{"schema_version":1,"architecture":"x64"',
            '{"architecture":"x64","schema_version":1'))),
        @('padded numeric spelling', $utf8.GetBytes($manifestText.Replace(
            '"schema_version":1', '"schema_version":01'))),
        @('wrong numeric type', $utf8.GetBytes($manifestText.Replace(
            '"protocol_version":1', '"protocol_version":"1"'))),
        @('wrong authorization literal', $utf8.GetBytes($manifestText.Replace(
            '"install_authorized":false', '"install_authorized":true'))),
        @('duplicate file property', $utf8.GetBytes($manifestText.Replace(
            '{"filename":"INSTALL-GATE.md",',
            '{"filename":"INSTALL-GATE.md","filename":"INSTALL-GATE.md",'))),
        @('unknown file property', $utf8.GetBytes($manifestText.Replace(
            '{"filename":"INSTALL-GATE.md",',
            '{"filename":"INSTALL-GATE.md","unknown":0,'))),
        @('misordered file properties', $utf8.GetBytes([regex]::Replace($manifestText,
            '\{"filename":"INSTALL-GATE\.md","size":([0-9]+)',
            '{"size":$1,"filename":"INSTALL-GATE.md"', 1))),
        @('padded file size', $utf8.GetBytes([regex]::Replace($manifestText,
            '("filename":"INSTALL-GATE\.md","size":)([0-9]+)', '${1}0$2', 1))),
        @('escaped fixed filename', $utf8.GetBytes($manifestText.Replace(
            '"filename":"README.md"', '"filename":"README\u002emd"'))),
        @('misordered file entries', $utf8.GetBytes($swappedFiles)),
        @('missing file entry', $utf8.GetBytes($manifestText.Replace(
            $fileObjects[0].Value + ',', ''))),
        @('unknown file entry', $utf8.GetBytes($manifestText.Replace(
            $fileObjects[0].Value, '{"filename":"unknown.bin","size":1,"sha256":"' +
            ('0' * 64) + '"}')))
    )
    foreach ($case in $manifestCases) {
        Test-ByteMutation $packageA 'package-manifest.json' $case[1] $manifest $case[0]
    }

    $checksumLines = @($checksumText.TrimEnd("`n").Split("`n"))
    $checksumCases = @(
        @('checksum BOM', ([byte[]](0xEF, 0xBB, 0xBF) + $checksums)),
        @('checksum CRLF', $utf8.GetBytes($checksumText.Replace("`n", "`r`n"))),
        @('checksum missing LF', $utf8.GetBytes($checksumText.TrimEnd("`n"))),
        @('checksum extra LF', $utf8.GetBytes($checksumText + "`n")),
        @('checksum uppercase hash', $utf8.GetBytes($checksumText.Substring(0, 64).ToUpperInvariant() +
            $checksumText.Substring(64))),
        @('checksum one separator', $utf8.GetBytes([regex]::Replace($checksumText,
            '^([0-9a-f]{64})  ', '$1 ', 1))),
        @('checksum reordered lines', $utf8.GetBytes((@($checksumLines[1], $checksumLines[0]) +
            $checksumLines[2..($checksumLines.Count - 1)] -join "`n") + "`n")),
        @('checksum missing member', $utf8.GetBytes(($checksumLines[1..($checksumLines.Count - 1)] -join "`n") + "`n"))
    )
    foreach ($case in $checksumCases) {
        Test-ByteMutation $packageA 'SHA256SUMS.txt' $case[1] $checksums $case[0]
    }

    $brokerPath = Join-Path $packageA 'faultloom_broker.exe'
    $broker = [IO.File]::ReadAllBytes($brokerPath)
    $substitute = [byte[]]$broker.Clone()
    $substitute[$substitute.Length - 1] = $substitute[$substitute.Length - 1] -bxor 1
    Test-ByteMutation $packageA 'faultloom_broker.exe' $substitute $broker 'substituted binary'

    $readmePath = Join-Path $packageA 'README.md'
    $readme = [IO.File]::ReadAllBytes($readmePath)
    try {
        [IO.File]::Delete($readmePath)
        Assert-VerifyFailsReadOnly $packageA 'missing member'
    } finally {
        [IO.File]::WriteAllBytes($readmePath, $readme)
    }
    $unexpected = Join-Path $packageA 'unexpected.txt'
    try {
        [IO.File]::WriteAllBytes($unexpected, [byte[]](1, 2, 3))
        Assert-VerifyFailsReadOnly $packageA 'unexpected member'
    } finally {
        if ([IO.File]::Exists($unexpected)) { [IO.File]::Delete($unexpected) }
    }
    $junction = Join-Path $packageA 'unexpected-link'
    try {
        New-Item -ItemType Junction -Path $junction -Target $packageA | Out-Null
        Assert-VerifyFailsReadOnly $packageA 'reparse member'
    } finally {
        if ([IO.Directory]::Exists($junction)) {
            cmd.exe /d /c rmdir $junction
            Assert-Condition ($LASTEXITCODE -eq 0) 'junction cleanup failed'
        }
    }
    Assert-VerifyPasses $packageA

    $outside = Join-Path $repository 'native\windows_authority\package-outside-probe'
    Assert-Condition (-not [IO.Directory]::Exists($outside) -and -not [IO.File]::Exists($outside)) `
        'outside probe already exists'
    $outsideResult = Invoke-Isolated $packageScript @('-BuildDir', $BuildDir, '-Configuration',
        'Release', '-OutputDir', $outside)
    Assert-Condition ($outsideResult.ExitCode -ne 0) 'outside package output was accepted'
    Assert-Condition (-not [IO.Directory]::Exists($outside) -and -not [IO.File]::Exists($outside)) `
        'outside package path was touched'
    $sourceReadme = Join-Path $repository 'native\windows_authority\README.md'
    $sourceHash = Get-Sha256 $sourceReadme
    $sourceWrite = ([IO.FileInfo]::new($sourceReadme)).LastWriteTimeUtc.Ticks
    $verifyOutside = Invoke-Isolated $verifyScript @('-PackageDir',
        (Join-Path $repository 'native\windows_authority'))
    Assert-Condition ($verifyOutside.ExitCode -ne 0) 'outside verifier input was accepted'
    Assert-Condition ((Get-Sha256 $sourceReadme) -ceq $sourceHash -and
        ([IO.FileInfo]::new($sourceReadme)).LastWriteTimeUtc.Ticks -eq $sourceWrite) `
        'outside verifier input was touched'

    $installProbe = Join-Path $packageRoot 'todo6-install-probe'
    $installResult = Invoke-Isolated $packageScript @('-BuildDir', $BuildDir, '-Configuration',
        'Release', '-OutputDir', $installProbe, '-Install')
    Assert-Condition ($installResult.ExitCode -ne 0) 'nonexistent install switch was accepted'
    Assert-Condition (-not [IO.Directory]::Exists($installProbe)) 'install switch created output'
    $debugResult = Invoke-Isolated $packageScript @('-BuildDir', $BuildDir, '-Configuration',
        'Debug', '-OutputDir', $installProbe)
    Assert-Condition ($debugResult.ExitCode -ne 0) 'non-Release configuration was accepted'
    $foreignBuild = Invoke-Isolated $packageScript @('-BuildDir',
        (Join-Path $repository 'native\windows_authority'), '-Configuration', 'Release',
        '-OutputDir', $installProbe)
    Assert-Condition ($foreignBuild.ExitCode -ne 0) 'foreign build input was accepted'
    Assert-CleanRootVerifierFailsReadOnly 'missing' $false
    Assert-CleanRootVerifierFailsReadOnly 'outside' $true
} finally {
    Remove-OwnedPackage $packageA
    Remove-OwnedPackage $packageB
    Remove-OwnedPackage $contractFixtureRoot
}

[Console]::Out.WriteLine('PACKAGE_TESTS_OK')
