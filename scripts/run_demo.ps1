<#
.SYNOPSIS
    Run the deterministic Sentinel 0.1.1 demo; Python owns its disposable profile.
#>
[CmdletBinding()]
param(
    [string]$PluginDir = '',
    [string]$PythonExe = 'python'
)

$ErrorActionPreference = 'Stop'
if (-not $PluginDir) {
    $PluginDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}
$DemoScript = Join-Path $PluginDir 'scripts\run_demo.py'
if (-not (Test-Path -LiteralPath $DemoScript -PathType Leaf)) {
    throw "Demo script not found: $DemoScript"
}
& $PythonExe -B $DemoScript
if ($LASTEXITCODE -ne 0) {
    throw "Demo failed with exit code $LASTEXITCODE"
}
