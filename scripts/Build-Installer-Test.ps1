[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Build-Installer.ps1') `
    -Configuration $Configuration `
    -FastDependencyPackaging $true `
    -TestBuild $true
