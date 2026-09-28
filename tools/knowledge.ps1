<# Run the source-only reference workspace with an already-installed Python 3.12. #>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Python,
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$CommandArgs
)
$ErrorActionPreference = 'Stop'
$runtimeSource = Join-Path (Split-Path -Parent $PSScriptRoot) 'packages\runtime\src'
$previousPythonPath = $env:PYTHONPATH
$previousUtf8 = $env:PYTHONUTF8
$previousBytecode = $env:PYTHONDONTWRITEBYTECODE
$pythonArguments = @()
if ($Python) {
    $pythonCommand = $Python
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCommand = (Get-Command py).Source
    $pythonArguments = @('-3.12')
} else {
    $pythonCommand = (Get-Command python -ErrorAction Stop).Source
}
try {
    & $pythonCommand @pythonArguments -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 2)'
    if ($LASTEXITCODE -ne 0) { throw 'An installed Python 3.12 is required. Use -Python to select its executable.' }
    $env:PYTHONPATH = if ($previousPythonPath) { $runtimeSource + [IO.Path]::PathSeparator + $previousPythonPath } else { $runtimeSource }
    $env:PYTHONUTF8 = '1'
    $env:PYTHONDONTWRITEBYTECODE = '1'
    & $pythonCommand @pythonArguments -m faultloom.knowledge_cli @CommandArgs
    $resultCode = $LASTEXITCODE
} finally {
    $env:PYTHONPATH = $previousPythonPath
    $env:PYTHONUTF8 = $previousUtf8
    $env:PYTHONDONTWRITEBYTECODE = $previousBytecode
}
exit $resultCode
