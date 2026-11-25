[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppDirectory,
    [Parameter(Mandatory = $false)]
    [string]$PreviousInstallDir = '',
    [Parameter(Mandatory = $false)]
    [ValidateSet('Install', 'Uninstall')]
    [string]$Mode = 'Install'
)

$ErrorActionPreference = 'SilentlyContinue'

function Normalize-DirectoryPrefix([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try {
        $clean = $Path.Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($clean)) { return $null }
        $full = [System.IO.Path]::GetFullPath($clean)
        $root = [System.IO.Path]::GetPathRoot($full)
        if ($full.Length -gt $root.Length) {
            $full = $full.TrimEnd('\', '/')
        }
        return ($full.TrimEnd('\', '/') + '\')
    }
    catch {
        return $null
    }
}

$upgradeInProgress = ($Mode -eq 'Install')
if (-not $upgradeInProgress) {
    foreach ($regPath in @('HKLM:\SOFTWARE\MCPHotplug', 'HKLM:\SOFTWARE\MCPBridge')) {
        try {
            $val = Get-ItemPropertyValue -LiteralPath $regPath -Name 'UpgradeInProgress' -ErrorAction Stop
            if ([string]$val -eq '1') {
                $upgradeInProgress = $true
                break
            }
        }
        catch { }
    }
}

$appPrefixes = [System.Collections.Generic.List[string]]::new()
foreach ($candidate in @($AppDirectory, $PreviousInstallDir)) {
    $norm = Normalize-DirectoryPrefix $candidate
    if ($norm -and -not ($appPrefixes -contains $norm)) {
        $appPrefixes.Add($norm)
    }
}

function Test-PathUnderApp([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        $full = [System.IO.Path]::GetFullPath($Path.Trim().Trim('"'))
        foreach ($prefix in $appPrefixes) {
            if ($full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    }
    catch { }
    return $false
}

function Test-CommandLineReferencesApp([string]$CommandLine) {
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
    foreach ($prefix in $appPrefixes) {
        $dirNoSlash = $prefix.TrimEnd('\')
        if ($CommandLine.IndexOf($dirNoSlash, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Get-ProcessSnapshot {
    $byId = @{}
    $childrenByParent = @{}
    $items = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)
    foreach ($item in $items) {
        $procId = [int]$item.ProcessId
        $parentId = [int]$item.ParentProcessId
        $byId[$procId] = $item
        if (-not $childrenByParent.ContainsKey($parentId)) {
            $childrenByParent[$parentId] = [System.Collections.Generic.List[int]]::new()
        }
        $childrenByParent[$parentId].Add($procId)
    }
    return @{
        ById = $byId
        ChildrenByParent = $childrenByParent
    }
}

function Get-ProtectedAncestorPids([hashtable]$ById) {
    $protected = [System.Collections.Generic.HashSet[int]]::new()
    $current = [int]$PID
    while ($current -gt 0 -and $protected.Add($current)) {
        if (-not $ById.ContainsKey($current)) { break }
        $current = [int]$ById[$current].ParentProcessId
    }
    return $protected
}

function Test-IsProtectedProcess($Proc, [System.Collections.Generic.HashSet[int]]$ProtectedPids) {
    $procId = [int]$Proc.ProcessId
    if ($ProtectedPids.Contains($procId)) { return $true }

    $name = [string]$Proc.Name
    if ($name -match '^unins\d*\.exe$') { return $true }
    if ($upgradeInProgress) {
        if ($name -match '^MCP(?:Hotplug|Bridge)\.Updater(?:\.Worker\.[^.]+)?\.exe$') { return $true }
        if ($name -match '^MCP-(?:Hotplug|Bridge)-Setup-.*\.exe$') { return $true }
        $exePath = [string]$Proc.ExecutablePath
        if (-not [string]::IsNullOrWhiteSpace($exePath) -and $exePath -match '(?i)\\Updates\\') { return $true }
    }
    return $false
}

function Test-IsOwnedMcpHotplugProcess($Proc, [System.Collections.Generic.HashSet[int]]$ProtectedPids) {
    if (Test-IsProtectedProcess $Proc $ProtectedPids) { return $false }

    $name = [string]$Proc.Name
    $exePath = [string]$Proc.ExecutablePath
    $cmdLine = [string]$Proc.CommandLine

    if ($name -ieq 'MCPHotplug.exe' -or $name -ieq 'MCPBridge.exe') {
        return $true
    }

    if (-not $upgradeInProgress -and $name -match '^MCP(?:Hotplug|Bridge)\.Updater(?:\.Worker\.[^.]+)?\.exe$') {
        if ((Test-PathUnderApp $exePath) -or (Test-CommandLineReferencesApp $cmdLine)) {
            return $true
        }
    }

    if (Test-PathUnderApp $exePath) {
        return $true
    }

    if ($name -ieq 'supergateway.exe') {
        if ((Test-CommandLineReferencesApp $cmdLine) -or
            ($cmdLine -match '(?i)(filesystem-gateway\.json|composite-gateway\.json|CustomGateways\\gateway-)')) {
            return $true
        }
    }

    if ($name -ieq 'node.exe') {
        if ((Test-CommandLineReferencesApp $cmdLine) -or
            ($cmdLine -match '(?i)(roots-filter\.js|hotplug-mcp-gateway\.js|bridge-mcp-gateway\.js|binary-mcp\.js|hotplug-mcp-stdio\.js|mcp-poll-manager\.js)')) {
            return $true
        }
    }

    if ($name -ieq 'tailscale.exe') {
        if ($cmdLine -match '(?i)\bfunnel\b.*(--set-path=/mcp|127\.0\.0\.1:8004|/mcphotplug-test-)') {
            return $true
        }
    }

    if ($name -ieq 'powershell.exe' -and (Test-CommandLineReferencesApp $cmdLine)) {
        if ($cmdLine -match '(?i)Config\\Temp\\TailscaleSetup-') {
            return $true
        }
    }

    return $false
}

function Collect-SubtreePostOrder(
    [int]$RootPid,
    [hashtable]$ChildrenByParent,
    [System.Collections.Generic.HashSet[int]]$Visited,
    [System.Collections.Generic.List[int]]$Ordered
) {
    if (-not $Visited.Add($RootPid)) { return }
    if ($ChildrenByParent.ContainsKey($RootPid)) {
        foreach ($childPid in $ChildrenByParent[$RootPid]) {
            Collect-SubtreePostOrder $childPid $ChildrenByParent $Visited $Ordered
        }
    }
    $Ordered.Add($RootPid)
}

function Stop-OwnedProcessTrees {
    $terminated = [System.Collections.Generic.HashSet[int]]::new()

    for ($pass = 0; $pass -lt 2; $pass++) {
        $snapshot = Get-ProcessSnapshot
        $byId = $snapshot.ById
        $childrenByParent = $snapshot.ChildrenByParent
        $protectedPids = Get-ProtectedAncestorPids $byId

        $rootPids = [System.Collections.Generic.List[int]]::new()
        foreach ($proc in $byId.Values) {
            if (Test-IsOwnedMcpHotplugProcess $proc $protectedPids) {
                $rootPids.Add([int]$proc.ProcessId)
            }
        }

        if ($rootPids.Count -eq 0) {
            break
        }

        $visited = [System.Collections.Generic.HashSet[int]]::new()
        $ordered = [System.Collections.Generic.List[int]]::new()
        foreach ($rootPid in $rootPids) {
            Collect-SubtreePostOrder $rootPid $childrenByParent $visited $ordered
        }

        foreach ($targetPid in $ordered) {
            if ($byId.ContainsKey($targetPid) -and (Test-IsProtectedProcess $byId[$targetPid] $protectedPids)) {
                continue
            }
            $null = $terminated.Add($targetPid)
            try {
                Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
            }
            catch { }
        }

        Start-Sleep -Milliseconds 250
    }

    return $terminated
}

function Wait-ForTerminatedProcessesAndPorts([System.Collections.Generic.HashSet[int]]$TargetedPids) {
    $deadline = [DateTime]::UtcNow.AddSeconds(6)
    $managedPorts = @(8001, 8003, 8004, 8005, 18006) + (8010..8099)

    while ([DateTime]::UtcNow -lt $deadline) {
        $stillAlive = $false
        foreach ($targetPid in $TargetedPids) {
            if (Get-Process -Id $targetPid -ErrorAction SilentlyContinue) {
                $stillAlive = $true
                try { Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue } catch { }
            }
        }

        $ownedPortBusy = $false
        try {
            $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                Where-Object { $managedPorts -contains [int]$_.LocalPort })
            if ($listeners.Count -gt 0) {
                $snapshot = Get-ProcessSnapshot
                $protectedPids = Get-ProtectedAncestorPids $snapshot.ById
                foreach ($listener in $listeners) {
                    $ownerPid = [int]$listener.OwningProcess
                    if ($ownerPid -le 0) { continue }

                    if ($TargetedPids.Contains($ownerPid)) {
                        $ownedPortBusy = $true
                        continue
                    }

                    if ($snapshot.ById.ContainsKey($ownerPid)) {
                        $ownerProc = $snapshot.ById[$ownerPid]
                        if (Test-IsOwnedMcpHotplugProcess $ownerProc $protectedPids) {
                            $ownedPortBusy = $true
                            $null = $TargetedPids.Add($ownerPid)
                            try { Stop-Process -Id $ownerPid -Force -ErrorAction SilentlyContinue } catch { }
                        }
                    }
                }
            }
        }
        catch { }

        if (-not $stillAlive -and -not $ownedPortBusy) {
            break
        }

        Start-Sleep -Milliseconds 200
    }
}

$targeted = Stop-OwnedProcessTrees
Wait-ForTerminatedProcessesAndPorts $targeted
exit 0
