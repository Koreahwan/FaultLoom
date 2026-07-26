[CmdletBinding()]
param(
    [switch]$SkipDependencyInstall
)

$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output = Join-Path $repository 'out\personal-cli'
$environment = Join-Path $output 'build-venv'
$python = Join-Path $environment 'Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    & py -3.12 -m venv $environment
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 virtual environment creation failed' }
}

if (-not $SkipDependencyInstall) {
    & $python -m pip install --disable-pip-version-check `
        cryptography==41.0.7 pydantic==2.12.5 playwright==1.58.0 `
        pyinstaller==6.14.2
    if ($LASTEXITCODE -ne 0) { throw 'Personal CLI build dependency installation failed' }
}

$arguments = @(
    '-m', 'PyInstaller',
    '--noconfirm', '--clean', '--onefile', '--name', 'faultloom',
    '--distpath', (Join-Path $output 'dist'),
    '--workpath', (Join-Path $output 'build'),
    '--specpath', $output
)
foreach ($path in @(
    'packages\protocol\src',
    'packages\sdk\src',
    'packages\runtime\src',
    'packs\web\src',
    'packs\llm\src',
    'packs\advanced_web\src',
    'packs\cloud\src',
    'packs\mobile\src',
    'packs\web3\src'
)) {
    $arguments += @('--paths', (Join-Path $repository $path))
}
$arguments += @(
    '--hidden-import', 'faultloom_web',
    '--hidden-import', 'faultloom_web.web_api',
    '--hidden-import', 'faultloom_web.web_api.manifest',
    '--hidden-import', 'faultloom_llm',
    '--hidden-import', 'faultloom_llm.manifest',
    '--hidden-import', 'faultloom_advanced_web',
    '--hidden-import', 'faultloom_advanced_web.manifest',
    '--hidden-import', 'faultloom_cloud',
    '--hidden-import', 'faultloom_cloud.manifest',
    '--hidden-import', 'faultloom_mobile',
    '--hidden-import', 'faultloom_mobile.manifest',
    '--hidden-import', 'faultloom_web3',
    '--hidden-import', 'faultloom_web3.manifest',
    (Join-Path $repository 'tools\faultloom_windows_entry.py')
)

& $python @arguments
if ($LASTEXITCODE -ne 0) { throw 'FaultLoom personal Windows CLI build failed' }

$release = Join-Path $output 'release'
[IO.Directory]::CreateDirectory($release) | Out-Null
$executable = Join-Path $output 'dist\faultloom.exe'
$releasedExecutable = Join-Path $release 'faultloom.exe'
[IO.File]::Copy($executable, $releasedExecutable, $true)
[IO.File]::Copy(
    (Join-Path $repository 'docs\PERSONAL_WINDOWS_QUICKSTART.md'),
    (Join-Path $release 'README.md'),
    $true
)
$stream = [IO.File]::OpenRead($releasedExecutable)
try {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = -join ($hasher.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $hasher.Dispose()
    }
}
finally {
    $stream.Dispose()
}
[IO.File]::WriteAllText(
    (Join-Path $release 'SHA256SUMS.txt'),
    "$digest  faultloom.exe`n",
    [Text.UTF8Encoding]::new($false)
)

& $releasedExecutable doctor --json
if ($LASTEXITCODE -ne 0) { throw 'Built FaultLoom executable failed its doctor check' }
Write-Output "READY $releasedExecutable"
