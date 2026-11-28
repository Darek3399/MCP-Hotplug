[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [bool]$LaunchAfterPublish = $true
)

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Publish-Windows.ps1') `
    -Configuration $Configuration `
    -LaunchAfterPublish $LaunchAfterPublish `
    -TestBuild $true
