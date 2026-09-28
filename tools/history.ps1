<# Run private work-history commands with an installed Python 3.12 runtime. #>
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
    & $pythonCommand @pythonArguments -c 'import sys, importlib.util; sys.exit(0 if sys.version_info[:2] == (3, 12) and importlib.util.find_spec("cryptography") else 2)'
    if ($LASTEXITCODE -ne 0) { throw 'Select an installed Python 3.12 runtime with cryptography using -Python. This launcher does not install dependencies.' }
    $env:PYTHONPATH = if ($previousPythonPath) { $runtimeSource + [IO.Path]::PathSeparator + $previousPythonPath } else { $runtimeSource }
    $env:PYTHONUTF8 = '1'
    $env:PYTHONDONTWRITEBYTECODE = '1'
    & $pythonCommand @pythonArguments -m faultloom.history_cli @CommandArgs
    $resultCode = $LASTEXITCODE
} finally {
    $env:PYTHONPATH = $previousPythonPath
    $env:PYTHONUTF8 = $previousUtf8
    $env:PYTHONDONTWRITEBYTECODE = $previousBytecode
}
exit $resultCode
