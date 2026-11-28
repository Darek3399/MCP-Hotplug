using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace McpHotplug.Services;

internal sealed class TrackedUnrealEditor
{
    public int ProcessId { get; set; }
    public string UProjectPath { get; set; } = string.Empty;
    public string ProjectName { get; set; } = string.Empty;
    public string ProjectDirectory { get; set; } = string.Empty;
    public string EngineRoot { get; set; } = string.Empty;
    public string EditorExecutable { get; set; } = string.Empty;
    public string? EngineVersion { get; set; }
    public DateTime StartTimeUtc { get; set; }
}

internal sealed class UnrealProjectTarget
{
    public string UProjectPath { get; set; } = string.Empty;
    public string ProjectName { get; set; } = string.Empty;
    public string ProjectDirectory { get; set; } = string.Empty;
    public string EngineRoot { get; set; } = string.Empty;
    public string EditorExecutable { get; set; } = string.Empty;
    public string? EngineVersion { get; set; }
    public string? EditorTarget { get; set; }
    public bool IsCppProject => !string.IsNullOrWhiteSpace(EditorTarget);

    public UnrealProjectTarget Clone() => new()
    {
        UProjectPath = UProjectPath,
        ProjectName = ProjectName,
        ProjectDirectory = ProjectDirectory,
        EngineRoot = EngineRoot,
        EditorExecutable = EditorExecutable,
        EngineVersion = EngineVersion,
        EditorTarget = EditorTarget
    };
}

internal sealed class EditorWindowReadiness
{
    public bool HasMainUnrealWindow { get; set; }
    public bool HasSplashWindow { get; set; }
    public bool IsResponsive { get; set; }
    public bool HasModalDialog { get; set; }
    public string? ModalDialogTitle { get; set; }
}

internal sealed class UnrealEditorTracker : IDisposable
{
    private const string EditorProcessName = "UnrealEditor";
    private const string EditorProcessFileName = "UnrealEditor.exe";
    private const string BuildBatchRelativePath = @"Engine\Build\BatchFiles\Build.bat";
    private const string RebuildBatchRelativePath = @"Engine\Build\BatchFiles\Rebuild.bat";
    private const string EditorExeRelativePath = @"Engine\Binaries\Win64\UnrealEditor.exe";
    private const string BuildVersionRelativePath = @"Engine\Build\Build.version";
    private const int ScanIntervalMs = 2500;

    private readonly object _sync = new();
    private readonly Dictionary<int, TrackedEntry> _trackedByPid = new();
    private System.Threading.Timer? _scanTimer;
    private int _scanInProgress;
    private bool _disposed;
    private UnrealProjectTarget? _activeTarget;
    private string? _lockedProjectPath;

    public UnrealEditorTracker()
    {
        LoadPersistedTarget();
    }

    public void Start()
    {
        lock (_sync)
        {
            if (_disposed || _scanTimer != null) return;
            _scanTimer = new System.Threading.Timer(
                _ => ScanProcessesSafe(),
                null,
                TimeSpan.Zero,
                TimeSpan.FromMilliseconds(ScanIntervalMs));
        }
    }

    public void Stop()
    {
        System.Threading.Timer? timer;
        List<Process> processesToDispose;
        lock (_sync)
        {
            timer = _scanTimer;
            _scanTimer = null;
            processesToDispose = _trackedByPid.Values.Select(e => e.ProcessHandle).Where(p => p != null).Cast<Process>().ToList();
            _trackedByPid.Clear();
        }

        timer?.Dispose();
        foreach (var proc in processesToDispose)
        {
            try { proc.Dispose(); } catch { }
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
        }
        Stop();
    }

    public void LockActiveProjectForBuild(string uprojectPath)
    {
        lock (_sync)
        {
            _lockedProjectPath = NormalizeFilePath(uprojectPath);
        }
    }

    public void UnlockBuildProject()
    {
        lock (_sync)
        {
            _lockedProjectPath = null;
        }
        RefreshNow();
    }

    public void RefreshNow()
    {
        ScanProcessesCore();
    }

    public List<TrackedUnrealEditor> GetRunningEditors(bool refresh = true)
    {
        if (refresh) ScanProcessesCore();
        lock (_sync)
        {
            return _trackedByPid.Values
                .Select(e => CloneEditor(e.Info))
                .OrderBy(e => e.StartTimeUtc)
                .ThenBy(e => e.ProcessId)
                .ToList();
        }
    }

    public List<int> GetRunningPidsForProject(string uprojectPath, bool refresh = true)
    {
        if (refresh) ScanProcessesCore();
        var normalized = NormalizeFilePath(uprojectPath);
        lock (_sync)
        {
            return _trackedByPid.Values
                .Where(e => string.Equals(e.Info.UProjectPath, normalized, StringComparison.OrdinalIgnoreCase))
                .OrderBy(e => e.Info.StartTimeUtc)
                .ThenBy(e => e.Info.ProcessId)
                .Select(e => e.Info.ProcessId)
                .ToList();
        }
    }

    public int GetOtherRunningEditorsCount(string uprojectPath)
    {
        var normalized = NormalizeFilePath(uprojectPath);
        lock (_sync)
        {
            return _trackedByPid.Values
                .Count(e => !string.Equals(e.Info.UProjectPath, normalized, StringComparison.OrdinalIgnoreCase));
        }
    }

    public UnrealProjectTarget? GetActiveTarget(bool refresh = true)
    {
        if (refresh) ScanProcessesCore();
        lock (_sync)
        {
            return _activeTarget?.Clone();
        }
    }

    public UnrealProjectTarget? ResolveProjectTarget(string? projectSelector, int? pid, bool pinAsActive)
    {
        ScanProcessesCore();

        if (pid.HasValue && pid.Value > 0)
        {
            TrackedUnrealEditor? byPid;
            lock (_sync)
            {
                byPid = _trackedByPid.TryGetValue(pid.Value, out var entry) ? CloneEditor(entry.Info) : null;
            }
            if (byPid == null) return null;
            var resolved = BuildTargetFromEditor(byPid);
            if (pinAsActive) SetActiveTarget(resolved);
            return resolved;
        }

        if (!string.IsNullOrWhiteSpace(projectSelector))
        {
            var selector = projectSelector!.Trim().Trim('"');

            // 1. Direct .uproject file path
            if (selector.EndsWith(".uproject", StringComparison.OrdinalIgnoreCase) && File.Exists(selector))
            {
                var normalized = NormalizeFilePath(selector);
                var running = GetRunningEditors(refresh: false)
                    .FirstOrDefault(e => string.Equals(e.UProjectPath, normalized, StringComparison.OrdinalIgnoreCase));
                var resolved = running != null
                    ? BuildTargetFromEditor(running)
                    : BuildTargetFromUProjectPath(normalized, null, null);
                if (resolved != null && pinAsActive) SetActiveTarget(resolved);
                return resolved;
            }

            // 2. Project directory containing a .uproject
            if (Directory.Exists(selector))
            {
                var uproject = Directory.GetFiles(selector, "*.uproject", SearchOption.TopDirectoryOnly).FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(uproject))
                {
                    var normalized = NormalizeFilePath(uproject);
                    var running = GetRunningEditors(refresh: false)
                        .FirstOrDefault(e => string.Equals(e.UProjectPath, normalized, StringComparison.OrdinalIgnoreCase));
                    var resolved = running != null
                        ? BuildTargetFromEditor(running)
                        : BuildTargetFromUProjectPath(normalized, null, null);
                    if (resolved != null && pinAsActive) SetActiveTarget(resolved);
                    return resolved;
                }
            }

            // 3. Match by running editor project name or path substring
            var runningList = GetRunningEditors(refresh: false);
            var matchedRunning = runningList.FirstOrDefault(e =>
                string.Equals(e.ProjectName, selector, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Path.GetFileName(e.UProjectPath), selector, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(e.UProjectPath, selector, StringComparison.OrdinalIgnoreCase));
            if (matchedRunning != null)
            {
                var resolved = BuildTargetFromEditor(matchedRunning);
                if (pinAsActive) SetActiveTarget(resolved);
                return resolved;
            }

            // 4. Match active remembered target even if closed
            lock (_sync)
            {
                if (_activeTarget != null &&
                    (string.Equals(_activeTarget.ProjectName, selector, StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(_activeTarget.UProjectPath, selector, StringComparison.OrdinalIgnoreCase)))
                {
                    return RefreshTargetMetadata(_activeTarget);
                }
            }

            return null;
        }

        // Default: active target (refreshed with current metadata)
        UnrealProjectTarget? current;
        lock (_sync) { current = _activeTarget?.Clone(); }
        if (current == null) return null;

        var refreshed = RefreshTargetMetadata(current);
        if (refreshed != null && pinAsActive) SetActiveTarget(refreshed);
        return refreshed;
    }

    public static string? GetBuildBatchPath(string engineRoot, bool fullRebuild)
    {
        if (string.IsNullOrWhiteSpace(engineRoot)) return null;
        var relative = fullRebuild ? RebuildBatchRelativePath : BuildBatchRelativePath;
        var path = Path.Combine(engineRoot, relative);
        return File.Exists(path) ? path : null;
    }

    private void SetActiveTarget(UnrealProjectTarget target)
    {
        lock (_sync)
        {
            _activeTarget = target.Clone();
        }
        PersistTarget(target);
    }

    private void ScanProcessesSafe()
    {
        try
        {
            ScanProcessesCore();
        }
        catch (Exception ex)
        {
            ErrorLog.Write("UnrealEditorTracker.ScanProcesses", ex);
        }
    }

    private void ScanProcessesCore()
    {
        if (_disposed) return;
        if (Interlocked.CompareExchange(ref _scanInProgress, 1, 0) != 0) return;

        try
        {
            Process[] currentProcs;
            try
            {
                currentProcs = Process.GetProcessesByName(EditorProcessName);
            }
            catch
            {
                return;
            }

            var liveByPid = new Dictionary<int, Process>();
            try
            {
                foreach (var p in currentProcs)
                {
                    try
                    {
                        if (!p.HasExited)
                            liveByPid[p.Id] = p;
                        else
                            p.Dispose();
                    }
                    catch
                    {
                        try { p.Dispose(); } catch { }
                    }
                }

                List<int> unknownPids;
                List<int> gonePids;
                lock (_sync)
                {
                    unknownPids = liveByPid.Keys.Where(pid => !_trackedByPid.ContainsKey(pid)).ToList();
                    gonePids = _trackedByPid.Keys.Where(pid => !liveByPid.ContainsKey(pid)).ToList();
                }

                foreach (var gonePid in gonePids)
                {
                    RemoveTrackedPid(gonePid);
                }

                if (unknownPids.Count > 0)
                {
                    var wmiRecords = QueryUnrealEditorWmi(new HashSet<int>(unknownPids));
                    foreach (var pid in unknownPids)
                    {
                        if (!liveByPid.TryGetValue(pid, out var proc)) continue;
                        if (!wmiRecords.TryGetValue(pid, out var rec)) continue;

                        var uprojectPath = ExtractUProjectPathFromCommandLine(rec.CommandLine);
                        if (string.IsNullOrWhiteSpace(uprojectPath) || !File.Exists(uprojectPath))
                            continue;

                        var normalizedUProject = NormalizeFilePath(uprojectPath!);
                        var projectDir = Path.GetDirectoryName(normalizedUProject) ?? string.Empty;
                        var projectName = Path.GetFileNameWithoutExtension(normalizedUProject);
                        var exePath = !string.IsNullOrWhiteSpace(rec.ExecutablePath) && File.Exists(rec.ExecutablePath)
                            ? NormalizeFilePath(rec.ExecutablePath!)
                            : TryGetProcessExePath(proc) ?? string.Empty;
                        var engineRoot = FindEngineRootFromExecutable(exePath)
                            ?? ResolveEngineRootFromUProject(normalizedUProject)
                            ?? string.Empty;
                        var engineVersion = ReadEngineVersion(engineRoot);
                        var startUtc = rec.CreationDateUtc ?? TryGetStartTimeUtc(proc);

                        var info = new TrackedUnrealEditor
                        {
                            ProcessId = pid,
                            UProjectPath = normalizedUProject,
                            ProjectName = projectName,
                            ProjectDirectory = projectDir,
                            EngineRoot = engineRoot,
                            EditorExecutable = exePath,
                            EngineVersion = engineVersion,
                            StartTimeUtc = startUtc
                        };

                        // Keep process handle subscribed to Exited for instant reactive exit detection
                        var attached = false;
                        try
                        {
                            proc.EnableRaisingEvents = true;
                            var capturedPid = pid;
                            proc.Exited += (_, _) => OnTrackedProcessExited(capturedPid);
                            if (!proc.HasExited)
                            {
                                lock (_sync)
                                {
                                    if (!_disposed && !_trackedByPid.ContainsKey(pid))
                                    {
                                        _trackedByPid[pid] = new TrackedEntry(info, proc);
                                        attached = true;
                                    }
                                }
                            }
                        }
                        catch
                        {
                            attached = false;
                        }

                        if (attached)
                        {
                            liveByPid.Remove(pid); // ownership transferred to _trackedByPid
                        }
                    }
                }

                ReconcileActiveTargetSelection();
            }
            finally
            {
                foreach (var remaining in liveByPid.Values)
                {
                    try { remaining.Dispose(); } catch { }
                }
            }
        }
        finally
        {
            Interlocked.Exchange(ref _scanInProgress, 0);
        }
    }

    private void OnTrackedProcessExited(int pid)
    {
        RemoveTrackedPid(pid);
        ReconcileActiveTargetSelection();
    }

    private void RemoveTrackedPid(int pid)
    {
        TrackedEntry? removed = null;
        lock (_sync)
        {
            if (_trackedByPid.TryGetValue(pid, out removed))
                _trackedByPid.Remove(pid);
        }

        if (removed?.ProcessHandle != null)
        {
            try { removed.ProcessHandle.Dispose(); } catch { }
        }
    }

    private void ReconcileActiveTargetSelection()
    {
        UnrealProjectTarget? targetToPersist = null;

        lock (_sync)
        {
            if (_disposed) return;

            var runningOrdered = _trackedByPid.Values
                .Select(e => e.Info)
                .OrderBy(e => e.StartTimeUtc)
                .ThenBy(e => e.ProcessId)
                .ToList();

            if (!string.IsNullOrWhiteSpace(_lockedProjectPath))
            {
                // During a rebuild/relaunch, keep the active target pinned and just refresh metadata if it came back online
                var match = runningOrdered.FirstOrDefault(e =>
                    string.Equals(e.UProjectPath, _lockedProjectPath, StringComparison.OrdinalIgnoreCase));
                if (match != null)
                {
                    _activeTarget = BuildTargetFromEditor(match);
                    targetToPersist = _activeTarget.Clone();
                }
                else
                {
                    return;
                }
            }
            else if (runningOrdered.Count > 0)
            {
                if (_activeTarget == null)
                {
                    // Auto-pick the earliest launched editor
                    _activeTarget = BuildTargetFromEditor(runningOrdered[0]);
                    targetToPersist = _activeTarget.Clone();
                }
                else
                {
                    var activeRunning = runningOrdered.FirstOrDefault(e =>
                        string.Equals(e.UProjectPath, _activeTarget.UProjectPath, StringComparison.OrdinalIgnoreCase));
                    if (activeRunning != null)
                    {
                        // Refresh engine/exe details if needed
                        if (!string.Equals(_activeTarget.EngineRoot, activeRunning.EngineRoot, StringComparison.OrdinalIgnoreCase) ||
                            !string.Equals(_activeTarget.EditorExecutable, activeRunning.EditorExecutable, StringComparison.OrdinalIgnoreCase))
                        {
                            _activeTarget = BuildTargetFromEditor(activeRunning);
                            targetToPersist = _activeTarget.Clone();
                        }
                    }
                    else
                    {
                        // Active editor is not running (closed manually or remembered from previous session),
                        // but another editor IS running -> automatically switch to the earliest running editor.
                        _activeTarget = BuildTargetFromEditor(runningOrdered[0]);
                        targetToPersist = _activeTarget.Clone();
                    }
                }
            }
            // If runningOrdered.Count == 0, keep _activeTarget remembered (closed state) so rebuild/launch still works.
        }

        if (targetToPersist != null)
            PersistTarget(targetToPersist);
    }

    private UnrealProjectTarget BuildTargetFromEditor(TrackedUnrealEditor editor)
    {
        var engineRoot = !string.IsNullOrWhiteSpace(editor.EngineRoot)
            ? editor.EngineRoot
            : (ResolveEngineRootFromUProject(editor.UProjectPath) ?? string.Empty);
        var exePath = !string.IsNullOrWhiteSpace(editor.EditorExecutable) && File.Exists(editor.EditorExecutable)
            ? editor.EditorExecutable
            : ResolveEditorExecutable(engineRoot);
        return new UnrealProjectTarget
        {
            UProjectPath = editor.UProjectPath,
            ProjectName = editor.ProjectName,
            ProjectDirectory = editor.ProjectDirectory,
            EngineRoot = engineRoot,
            EditorExecutable = exePath,
            EngineVersion = editor.EngineVersion ?? ReadEngineVersion(engineRoot),
            EditorTarget = DiscoverEditorTargetName(editor.ProjectDirectory)
        };
    }

    private UnrealProjectTarget? BuildTargetFromUProjectPath(string uprojectPath, string? hintEngineRoot, string? hintEditorExe)
    {
        if (string.IsNullOrWhiteSpace(uprojectPath) || !File.Exists(uprojectPath)) return null;
        var normalized = NormalizeFilePath(uprojectPath);
        var projectDir = Path.GetDirectoryName(normalized) ?? string.Empty;
        var projectName = Path.GetFileNameWithoutExtension(normalized);

        var engineRoot = (!string.IsNullOrWhiteSpace(hintEngineRoot) && IsValidEngineRoot(hintEngineRoot!))
            ? NormalizeFilePath(hintEngineRoot!)
            : (ResolveEngineRootFromUProject(normalized) ?? string.Empty);
        var editorExe = (!string.IsNullOrWhiteSpace(hintEditorExe) && File.Exists(hintEditorExe))
            ? NormalizeFilePath(hintEditorExe!)
            : ResolveEditorExecutable(engineRoot);

        return new UnrealProjectTarget
        {
            UProjectPath = normalized,
            ProjectName = projectName,
            ProjectDirectory = projectDir,
            EngineRoot = engineRoot,
            EditorExecutable = editorExe,
            EngineVersion = ReadEngineVersion(engineRoot),
            EditorTarget = DiscoverEditorTargetName(projectDir)
        };
    }

    private UnrealProjectTarget? RefreshTargetMetadata(UnrealProjectTarget target)
    {
        if (string.IsNullOrWhiteSpace(target.UProjectPath) || !File.Exists(target.UProjectPath))
            return null;

        var running = GetRunningEditors(refresh: false)
            .FirstOrDefault(e => string.Equals(e.UProjectPath, target.UProjectPath, StringComparison.OrdinalIgnoreCase));
        if (running != null)
            return BuildTargetFromEditor(running);

        return BuildTargetFromUProjectPath(target.UProjectPath, target.EngineRoot, target.EditorExecutable);
    }

    private void LoadPersistedTarget()
    {
        try
        {
            if (!File.Exists(AppPaths.UnrealBuildStateFile)) return;
            var serializer = new DataContractJsonSerializer(typeof(PersistedBuildState));
            using var stream = File.OpenRead(AppPaths.UnrealBuildStateFile);
            if (serializer.ReadObject(stream) is not PersistedBuildState state) return;
            if (string.IsNullOrWhiteSpace(state.UProjectPath) || !File.Exists(state.UProjectPath)) return;

            var target = BuildTargetFromUProjectPath(state.UProjectPath!, state.EngineRoot, state.EditorExecutable);
            if (target != null)
                _activeTarget = target;
        }
        catch (Exception ex)
        {
            ErrorLog.Write("UnrealEditorTracker.LoadPersistedTarget", ex);
        }
    }

    private void PersistTarget(UnrealProjectTarget target)
    {
        try
        {
            AppPaths.EnsureDirectories();
            var state = new PersistedBuildState
            {
                UProjectPath = target.UProjectPath,
                EngineRoot = target.EngineRoot,
                EditorExecutable = target.EditorExecutable,
                UpdatedAtUtc = DateTime.UtcNow.ToString("O")
            };
            var serializer = new DataContractJsonSerializer(typeof(PersistedBuildState));
            var tmp = AppPaths.UnrealBuildStateFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
            using (var stream = File.Create(tmp))
            {
                serializer.WriteObject(stream, state);
                stream.Flush(true);
            }
            if (File.Exists(AppPaths.UnrealBuildStateFile))
                File.Replace(tmp, AppPaths.UnrealBuildStateFile, null);
            else
                File.Move(tmp, AppPaths.UnrealBuildStateFile);
        }
        catch (Exception ex)
        {
            ErrorLog.Write("UnrealEditorTracker.PersistTarget", ex);
        }
    }

    // =========================================================================
    // UNIVERSAL ENGINE & TARGET DISCOVERY (UE 5.1 - 5.9 / 6.x)
    // =========================================================================

    public static string? ExtractUProjectPathFromCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var tokens = McpServerConfigParser.SplitCommandLine(commandLine!);
        // Skip token 0 (executable path)
        for (var i = 1; i < tokens.Count; i++)
        {
            var token = tokens[i].Trim().Trim('"');
            if (string.IsNullOrWhiteSpace(token)) continue;

            if (token.StartsWith("-Project=", StringComparison.OrdinalIgnoreCase))
                token = token.Substring("-Project=".Length).Trim().Trim('"');

            if (token.EndsWith(".uproject", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var full = Path.GetFullPath(token);
                    if (File.Exists(full)) return full;
                }
                catch { }
            }
        }
        return null;
    }

    public static bool IsValidEngineRoot(string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory)) return false;
        try
        {
            return File.Exists(Path.Combine(directory!, BuildBatchRelativePath));
        }
        catch { return false; }
    }

    public static string? FindEngineRootFromExecutable(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath)) return null;
        try
        {
            var dir = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(executablePath!)) ?? string.Empty);
            for (var depth = 0; depth < 8 && dir != null; depth++, dir = dir.Parent)
            {
                if (IsValidEngineRoot(dir.FullName))
                    return NormalizeFilePath(dir.FullName);
            }
        }
        catch { }
        return null;
    }

    public static string ResolveEditorExecutable(string? engineRoot)
    {
        if (string.IsNullOrWhiteSpace(engineRoot)) return string.Empty;
        try
        {
            var candidate = Path.Combine(engineRoot!, EditorExeRelativePath);
            return File.Exists(candidate) ? NormalizeFilePath(candidate) : string.Empty;
        }
        catch { return string.Empty; }
    }

    public static string? ReadEngineVersion(string? engineRoot)
    {
        if (string.IsNullOrWhiteSpace(engineRoot)) return null;
        try
        {
            var versionPath = Path.Combine(engineRoot!, BuildVersionRelativePath);
            if (!File.Exists(versionPath)) return null;
            var json = File.ReadAllText(versionPath, Encoding.UTF8);
            if (McpServerConfigParser.DeserializeJson(json) is not IDictionary<string, object?> map)
                return null;
            if (map.TryGetValue("MajorVersion", out var maj) && map.TryGetValue("MinorVersion", out var min))
            {
                var patch = map.TryGetValue("PatchVersion", out var p) && p != null ? "." + p : string.Empty;
                return maj + "." + min + patch;
            }
        }
        catch { }
        return null;
    }

    public static string? ResolveEngineRootFromUProject(string uprojectPath)
    {
        if (string.IsNullOrWhiteSpace(uprojectPath) || !File.Exists(uprojectPath)) return null;

        string? association = null;
        try
        {
            var json = File.ReadAllText(uprojectPath, Encoding.UTF8);
            if (McpServerConfigParser.DeserializeJson(json) is IDictionary<string, object?> dict &&
                dict.TryGetValue("EngineAssociation", out var rawAssoc) && rawAssoc != null)
            {
                association = Convert.ToString(rawAssoc)?.Trim();
            }
        }
        catch { }

        // 1. Source build next to / above the project (empty EngineAssociation or relative path)
        if (string.IsNullOrWhiteSpace(association))
        {
            var dir = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(uprojectPath)) ?? string.Empty);
            for (var depth = 0; depth < 6 && dir != null; depth++, dir = dir.Parent)
            {
                if (IsValidEngineRoot(dir.FullName))
                    return NormalizeFilePath(dir.FullName);
            }
            return null;
        }

        // 2. Custom source build registered by GUID in HKCU\SOFTWARE\Epic Games\Unreal Engine\Builds
        var hkcuPath = TryReadRegistryEngineBuild(association!);
        if (IsValidEngineRoot(hkcuPath))
            return NormalizeFilePath(hkcuPath!);

        // 3. Official Launcher build in HKLM\SOFTWARE\EpicGames\Unreal Engine\<version>
        var hklmPath = TryReadHklmEngineInstall(association!);
        if (IsValidEngineRoot(hklmPath))
            return NormalizeFilePath(hklmPath!);

        // 4. Epic Games Launcher manifest (read-only)
        var launcherPath = TryReadLauncherInstalledDat(association!);
        if (IsValidEngineRoot(launcherPath))
            return NormalizeFilePath(launcherPath!);

        return null;
    }

    private static string? TryReadRegistryEngineBuild(string association)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Epic Games\Unreal Engine\Builds");
            var val = key?.GetValue(association) as string;
            if (!string.IsNullOrWhiteSpace(val)) return val!.Trim().Trim('"');
        }
        catch { }
        return null;
    }

    private static string? TryReadHklmEngineInstall(string association)
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = baseKey.OpenSubKey(@"SOFTWARE\EpicGames\Unreal Engine\" + association);
                var val = key?.GetValue("InstalledDirectory") as string;
                if (!string.IsNullOrWhiteSpace(val)) return val!.Trim().Trim('"');
            }
            catch { }
        }
        return null;
    }

    private static string? TryReadLauncherInstalledDat(string association)
    {
        try
        {
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var manifestPath = Path.Combine(programData, "Epic", "UnrealEngineLauncher", "LauncherInstalled.dat");
            if (!File.Exists(manifestPath)) return null;

            var json = File.ReadAllText(manifestPath, Encoding.UTF8);
            if (McpServerConfigParser.DeserializeJson(json) is not IDictionary<string, object?> root)
                return null;
            if (!root.TryGetValue("InstallationList", out var rawList) || rawList is not IList list)
                return null;

            var expectedAppName = association.StartsWith("UE_", StringComparison.OrdinalIgnoreCase)
                ? association
                : "UE_" + association;

            foreach (var item in list)
            {
                if (item is not IDictionary<string, object?> entry) continue;
                var appName = entry.TryGetValue("AppName", out var a) ? Convert.ToString(a) : null;
                var installLoc = entry.TryGetValue("InstallLocation", out var loc) ? Convert.ToString(loc) : null;
                if (string.Equals(appName, expectedAppName, StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(installLoc))
                {
                    return installLoc!.Trim().Trim('"');
                }
            }
        }
        catch { }
        return null;
    }

    public static string? DiscoverEditorTargetName(string projectDirectory)
    {
        if (string.IsNullOrWhiteSpace(projectDirectory)) return null;
        var sourceDir = Path.Combine(projectDirectory, "Source");
        if (!Directory.Exists(sourceDir)) return null;

        var targetFiles = new List<string>();
        try
        {
            targetFiles.AddRange(Directory.GetFiles(sourceDir, "*Editor.Target.cs", SearchOption.TopDirectoryOnly));
            if (targetFiles.Count == 0)
            {
                foreach (var sub in Directory.GetDirectories(sourceDir))
                {
                    try
                    {
                        targetFiles.AddRange(Directory.GetFiles(sub, "*Editor.Target.cs", SearchOption.TopDirectoryOnly));
                    }
                    catch { }
                }
            }
            if (targetFiles.Count == 0)
                targetFiles.AddRange(Directory.GetFiles(sourceDir, "*.Target.cs", SearchOption.TopDirectoryOnly));
        }
        catch
        {
            return null;
        }

        string? fallbackName = null;
        foreach (var file in targetFiles.OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var content = File.ReadAllText(file, Encoding.UTF8);
                var isExplicitEditor = Regex.IsMatch(content, @"TargetType\s*\.\s*Editor\b", RegexOptions.CultureInvariant);
                var classMatch = Regex.Match(content, @"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*TargetRules\b", RegexOptions.CultureInvariant);
                var targetName = classMatch.Success
                    ? StripTargetSuffix(classMatch.Groups[1].Value)
                    : StripTargetFileSuffix(Path.GetFileName(file));

                if (isExplicitEditor && !string.IsNullOrWhiteSpace(targetName))
                    return targetName;

                if (fallbackName == null && file.EndsWith("Editor.Target.cs", StringComparison.OrdinalIgnoreCase))
                    fallbackName = targetName;
            }
            catch { }
        }

        return fallbackName;
    }

    private static string StripTargetSuffix(string className)
    {
        return className.EndsWith("Target", StringComparison.Ordinal) && className.Length > "Target".Length
            ? className.Substring(0, className.Length - "Target".Length)
            : className;
    }

    private static string StripTargetFileSuffix(string fileName)
    {
        const string suffix = ".Target.cs";
        return fileName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
            ? fileName.Substring(0, fileName.Length - suffix.Length)
            : Path.GetFileNameWithoutExtension(fileName);
    }

    // =========================================================================
    // WIN32 WINDOW CONTROL & READINESS INSPECTION
    // =========================================================================

    public static bool PostCloseToProcessWindows(int pid)
    {
        var windows = EnumerateTopLevelWindows(pid, visibleOnly: true);
        var mainUnrealWindows = windows
            .Where(w => string.Equals(w.ClassName, "UnrealWindow", StringComparison.OrdinalIgnoreCase) && w.Owner == IntPtr.Zero)
            .ToList();
        var targets = mainUnrealWindows.Count > 0
            ? mainUnrealWindows
            : windows.Where(w => w.Owner == IntPtr.Zero).ToList();

        if (targets.Count == 0)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                return proc.CloseMainWindow();
            }
            catch
            {
                return false;
            }
        }

        var postedAny = false;
        foreach (var w in targets)
        {
            if (PostMessage(w.Handle, WmClose, IntPtr.Zero, IntPtr.Zero))
                postedAny = true;
        }
        return postedAny;
    }

    public static EditorWindowReadiness InspectEditorWindows(int pid)
    {
        var result = new EditorWindowReadiness();
        var windows = EnumerateTopLevelWindows(pid, visibleOnly: true);

        foreach (var w in windows)
        {
            var isUnrealMain = string.Equals(w.ClassName, "UnrealWindow", StringComparison.OrdinalIgnoreCase);
            var isSplash = w.ClassName.IndexOf("Splash", StringComparison.OrdinalIgnoreCase) >= 0;

            if (isSplash)
                result.HasSplashWindow = true;

            if (isUnrealMain)
            {
                // Owned UnrealWindow can be a floating Slate tab (Blueprint/Material editor), not necessarily modal.
                // Only treat the main frame being disabled (IsWindowEnabled == false) or a #32770 dialog as modal.
                if (w.Owner != IntPtr.Zero)
                    continue;

                result.HasMainUnrealWindow = true;

                if (!IsWindowEnabled(w.Handle))
                {
                    result.HasModalDialog = true;
                    var popup = GetLastActivePopup(w.Handle);
                    if (popup != IntPtr.Zero && popup != w.Handle)
                    {
                        var popupTitle = ReadWindowTitle(popup);
                        if (!string.IsNullOrWhiteSpace(popupTitle))
                            result.ModalDialogTitle = popupTitle;
                    }
                }

                if (!result.IsResponsive &&
                    SendMessageTimeout(w.Handle, WmNull, IntPtr.Zero, IntPtr.Zero, SmtoAbortIfHung, 1000, out _) != IntPtr.Zero)
                {
                    result.IsResponsive = true;
                }
            }
            else if (string.Equals(w.ClassName, "#32770", StringComparison.Ordinal))
            {
                result.HasModalDialog = true;
                if (string.IsNullOrWhiteSpace(result.ModalDialogTitle) && !string.IsNullOrWhiteSpace(w.Title))
                    result.ModalDialogTitle = w.Title;
            }
        }

        return result;
    }

    private static List<WindowInfo> EnumerateTopLevelWindows(int pid, bool visibleOnly)
    {
        var list = new List<WindowInfo>();
        EnumWindows((hwnd, _) =>
        {
            GetWindowThreadProcessId(hwnd, out var windowPid);
            if (unchecked((int)windowPid) != pid) return true;
            if (visibleOnly && !IsWindowVisible(hwnd)) return true;

            list.Add(new WindowInfo
            {
                Handle = hwnd,
                Owner = GetWindow(hwnd, GwOwner),
                ClassName = ReadWindowClass(hwnd),
                Title = ReadWindowTitle(hwnd)
            });
            return true;
        }, IntPtr.Zero);
        return list;
    }

    private static string ReadWindowClass(IntPtr hwnd)
    {
        var sb = new StringBuilder(256);
        var len = GetClassName(hwnd, sb, sb.Capacity);
        return len > 0 ? sb.ToString(0, len) : string.Empty;
    }

    private static string ReadWindowTitle(IntPtr hwnd)
    {
        var sb = new StringBuilder(256);
        var len = GetWindowText(hwnd, sb, sb.Capacity);
        return len > 0 ? sb.ToString(0, len) : string.Empty;
    }

    // =========================================================================
    // WMI & HELPERS
    // =========================================================================

    private static Dictionary<int, WmiProcessInfo> QueryUnrealEditorWmi(HashSet<int> filterPids)
    {
        var result = new Dictionary<int, WmiProcessInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, CommandLine, ExecutablePath, CreationDate FROM Win32_Process WHERE Name = '" + EditorProcessFileName + "'");
            using var collection = searcher.Get();
            foreach (ManagementObject item in collection)
            {
                using (item)
                {
                    var pid = Convert.ToInt32(item["ProcessId"]);
                    if (!filterPids.Contains(pid)) continue;
                    var cmdLine = Convert.ToString(item["CommandLine"]);
                    var exePath = Convert.ToString(item["ExecutablePath"]);
                    DateTime? createdUtc = null;
                    var rawDate = Convert.ToString(item["CreationDate"]);
                    if (!string.IsNullOrWhiteSpace(rawDate))
                    {
                        try { createdUtc = ManagementDateTimeConverter.ToDateTime(rawDate).ToUniversalTime(); }
                        catch { }
                    }
                    result[pid] = new WmiProcessInfo(cmdLine, exePath, createdUtc);
                }
            }
        }
        catch (Exception ex)
        {
            ErrorLog.Write("UnrealEditorTracker.QueryUnrealEditorWmi", ex);
        }
        return result;
    }

    private static string? TryGetProcessExePath(Process proc)
    {
        try { return proc.MainModule?.FileName; }
        catch { return null; }
    }

    private static DateTime TryGetStartTimeUtc(Process proc)
    {
        try { return proc.StartTime.ToUniversalTime(); }
        catch { return DateTime.UtcNow; }
    }

    public static string NormalizeFilePath(string path)
    {
        var full = Path.GetFullPath(path.Trim().Trim('"'));
        var root = Path.GetPathRoot(full) ?? string.Empty;
        return full.Length > root.Length
            ? full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            : full;
    }

    private static TrackedUnrealEditor CloneEditor(TrackedUnrealEditor src) => new()
    {
        ProcessId = src.ProcessId,
        UProjectPath = src.UProjectPath,
        ProjectName = src.ProjectName,
        ProjectDirectory = src.ProjectDirectory,
        EngineRoot = src.EngineRoot,
        EditorExecutable = src.EditorExecutable,
        EngineVersion = src.EngineVersion,
        StartTimeUtc = src.StartTimeUtc
    };

    private sealed class TrackedEntry
    {
        public TrackedEntry(TrackedUnrealEditor info, Process processHandle)
        {
            Info = info;
            ProcessHandle = processHandle;
        }
        public TrackedUnrealEditor Info { get; }
        public Process ProcessHandle { get; }
    }

    private sealed class WmiProcessInfo
    {
        public WmiProcessInfo(string? commandLine, string? executablePath, DateTime? creationDateUtc)
        {
            CommandLine = commandLine;
            ExecutablePath = executablePath;
            CreationDateUtc = creationDateUtc;
        }
        public string? CommandLine { get; }
        public string? ExecutablePath { get; }
        public DateTime? CreationDateUtc { get; }
    }

    private sealed class WindowInfo
    {
        public IntPtr Handle { get; set; }
        public IntPtr Owner { get; set; }
        public string ClassName { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
    }

    [DataContract]
    private sealed class PersistedBuildState
    {
        [DataMember(Name = "uprojectPath")]
        public string? UProjectPath { get; set; }

        [DataMember(Name = "engineRoot")]
        public string? EngineRoot { get; set; }

        [DataMember(Name = "editorExecutable")]
        public string? EditorExecutable { get; set; }

        [DataMember(Name = "updatedAtUtc")]
        public string? UpdatedAtUtc { get; set; }
    }

    private const uint WmNull = 0x0000;
    private const uint WmClose = 0x0010;
    private const uint SmtoAbortIfHung = 0x0002;
    private const uint GwOwner = 4;

    private delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowEnabled(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetLastActivePopup(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(
        IntPtr hWnd,
        uint msg,
        IntPtr wParam,
        IntPtr lParam,
        uint flags,
        uint timeout,
        out IntPtr result);
}
