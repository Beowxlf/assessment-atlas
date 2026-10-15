# Run from a reviewed checkout/download in your own account.
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$InstallerArguments)
$ErrorActionPreference = 'Stop'
$Installer = Join-Path $PSScriptRoot 'install.py'
if ($env:ATLAS_PYTHON) {
    & $env:ATLAS_PYTHON $Installer @InstallerArguments
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $Installer @InstallerArguments
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python $Installer @InstallerArguments
} else {
    throw 'Install Python 3.12 or newer from python.org, then run this installer again.'
}
exit $LASTEXITCODE
