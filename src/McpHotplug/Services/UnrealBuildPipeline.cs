using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace McpHotplug.Services;

internal sealed class UnrealBuildJobSnapshot
{
    public string JobId { get; set; } = string.Empty;
    public string Status { get; set; } = "in_progress";
    public string Phase { get; set; } = "initializing";
    public string? Progress { get; set; }
    public string ProjectName { get; set; } = string.Empty;
    public string UProjectPath { get; set; } = string.Empty;
    public string? EngineVersion { get; set; }
    public string Mode { get; set; } = "incremental";
    public bool LaunchAfter { get; set; }
    public double ElapsedSeconds { get; set; }
    public int? ExitCode { get; set; }
    public int? EditorPid { get; set; }
    public bool? UnrealMcpReady { get; set; }
    public List<int>? BlockingPids { get; set; }
    public string? Message { get; set; }
    public List<string>? Errors { get; set; }
    public bool LogAvailable { get; set; }
    public string? BuildLogPath { get; set; }
    public string? EditorLogPath { get; set; }
    public int OtherEditorsCount { get; set; }
    public bool IsTerminal => Status is "ready" or "build_failed" or "editor_crashed" or "close_blocked" or "no_cpp_target" or "cancelled" or "failed";
}

internal sealed class UnrealBuildPipeline : IDisposable
{
    private const int MaxStoredBuildLogs = 5;
    private const int MaxParsedErrors = 25;
    private const int HttpKeepAliveWindowMs = 45000;

    private static readonly Regex UbtStepRegex = new(@"^\s*\[(\d+/\d+)\]\s*(.+)$", RegexOptions.Compiled);
    private static readonly Regex MsvcErrorRegex = new(@":\s*(?:fatal\s+)?error\s+[A-Z]+\d+\s*:", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex ClangErrorRegex = new(@":\d+:\d+:\s*(?:fatal\s+)?error\s*:", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex LinkerErrorRegex = new(@"\b(?:fatal\s+)?error\s+LNK\d+\s*:", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex UhtErrorRegex = new(@"(?:^|\s)(?:Error|ERROR)\s*:\s*", RegexOptions.Compiled);
    private static readonly Regex UbtNoiseRegex = new(@"^\s*(?:Total execution time|Result:|BuildException:|See\s+log|at\s+UnrealBuildTool\.)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly UnrealEditorTracker _tracker;
    private readonly Func<int> _getUnrealMcpPort;
    private readonly object _sync = new();
    private readonly Dictionary<string, JobState> _jobsById = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _jobOrder = new();
    private int _jobCounter;
    private JobState? _activeJob;
    private bool _disposed;

    public UnrealBuildPipeline(UnrealEditorTracker tracker, Func<int> getUnrealMcpPort)
    {
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
        _getUnrealMcpPort = getUnrealMcpPort ?? (() => 8000);
    }

    public async Task<UnrealBuildJobSnapshot> StartRebuildAsync(
        UnrealProjectTarget target,
        string mode,
        bool launchAfter,
        bool forceClose,
        CancellationToken serverStopToken)
    {
        if (!target.IsCppProject || string.IsNullOrWhiteSpace(target.EditorTarget))
        {
            return new UnrealBuildJobSnapshot
            {
                JobId = string.Empty,
                Status = "no_cpp_target",
                Phase = "preflight",
                ProjectName = target.ProjectName,
                UProjectPath = target.UProjectPath,
                EngineVersion = target.EngineVersion,
                Mode = mode,
                LaunchAfter = launchAfter,
                Message = "No *Editor.Target.cs found under Source/. This appears to be a Blueprint-only project with no C++ Editor target to compile.",
                OtherEditorsCount = _tracker.GetOtherRunningEditorsCount(target.UProjectPath)
            };
        }

        var fullRebuild = string.Equals(mode, "rebuild", StringComparison.OrdinalIgnoreCase);
        var batchPath = UnrealEditorTracker.GetBuildBatchPath(target.EngineRoot, fullRebuild);
        if (string.IsNullOrWhiteSpace(batchPath))
        {
            return new UnrealBuildJobSnapshot
            {
                JobId = string.Empty,
                Status = "failed",
                Phase = "preflight",
                ProjectName = target.ProjectName,
                UProjectPath = target.UProjectPath,
                EngineVersion = target.EngineVersion,
                Mode = mode,
                LaunchAfter = launchAfter,
                Message = "Could not locate Engine\\Build\\BatchFiles\\" + (fullRebuild ? "Rebuild.bat" : "Build.bat") +
                          " for EngineRoot='" + target.EngineRoot + "'."
            };
        }

        if (launchAfter && (string.IsNullOrWhiteSpace(target.EditorExecutable) || !File.Exists(target.EditorExecutable)))
        {
            return new UnrealBuildJobSnapshot
            {
                JobId = string.Empty,
                Status = "failed",
                Phase = "preflight",
                ProjectName = target.ProjectName,
                UProjectPath = target.UProjectPath,
                EngineVersion = target.EngineVersion,
                Mode = mode,
                LaunchAfter = launchAfter,
                Message = "Could not locate UnrealEditor.exe under EngineRoot='" + target.EngineRoot + "'."
            };
        }

        JobState job;
        lock (_sync)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(UnrealBuildPipeline));
            if (_activeJob != null && !_activeJob.IsTerminal)
            {
                return BuildSnapshotLocked(_activeJob);
            }

            var id = "b_" + (++_jobCounter).ToString("D2");
            job = new JobState(id, target.Clone(), fullRebuild ? "rebuild" : "incremental", launchAfter, forceClose, batchPath!);
            _jobsById[id] = job;
            _jobOrder.Add(id);
            while (_jobOrder.Count > 20)
            {
                var oldest = _jobOrder[0];
                _jobOrder.RemoveAt(0);
                _jobsById.Remove(oldest);
            }
            _activeJob = job;
        }

        _tracker.LockActiveProjectForBuild(target.UProjectPath);
        job.RunTask = Task.Run(() => ExecutePipelineAsync(job, serverStopToken), CancellationToken.None);

        return await WaitForJobUpdateAsync(job, waitOnlyForTerminal: true, serverStopToken).ConfigureAwait(false);
    }

    public async Task<UnrealBuildJobSnapshot?> GetStatusAsync(string? jobId, bool cancel, CancellationToken serverStopToken)
    {
        JobState? job;
        lock (_sync)
        {
            job = ResolveJobLocked(jobId);
        }
        if (job == null) return null;

        if (cancel && !job.IsTerminal)
        {
            CancelJob(job);
            if (job.RunTask != null)
            {
                await Task.WhenAny(job.RunTask, Task.Delay(5000, serverStopToken)).ConfigureAwait(false);
            }
            lock (_sync)
            {
                return BuildSnapshotLocked(job);
            }
        }

        if (job.IsTerminal)
        {
            lock (_sync)
            {
                return BuildSnapshotLocked(job);
            }
        }

        return await WaitForJobUpdateAsync(job, waitOnlyForTerminal: false, serverStopToken).ConfigureAwait(false);
    }

    public async Task<Dictionary<string, object?>> CloseEditorsOnlyAsync(
        UnrealProjectTarget target,
        bool forceClose,
        CancellationToken serverStopToken)
    {
        var pids = _tracker.GetRunningPidsForProject(target.UProjectPath, refresh: true);
        if (pids.Count == 0)
        {
            return new Dictionary<string, object?>
            {
                ["status"] = "closed",
                ["project"] = target.ProjectName,
                ["closed_pids"] = Array.Empty<int>(),
                ["message"] = "No running editor windows for this project."
            };
        }

        var closeResult = await CloseEditorProcessesAsync(null, pids, forceClose, serverStopToken).ConfigureAwait(false);
        if (!closeResult.Closed)
        {
            return new Dictionary<string, object?>
            {
                ["status"] = "close_blocked",
                ["project"] = target.ProjectName,
                ["blocking_pids"] = closeResult.BlockingPids ?? new List<int>(),
                ["message"] = closeResult.Message
            };
        }

        _tracker.RefreshNow();
        return new Dictionary<string, object?>
        {
            ["status"] = "closed",
            ["project"] = target.ProjectName,
            ["closed_pids"] = pids
        };
    }

    public async Task<UnrealBuildJobSnapshot> LaunchEditorOnlyAsync(UnrealProjectTarget target, CancellationToken serverStopToken)
    {
        if (string.IsNullOrWhiteSpace(target.EditorExecutable) || !File.Exists(target.EditorExecutable))
        {
            return new UnrealBuildJobSnapshot
            {
                Status = "failed",
                Phase = "launching",
                ProjectName = target.ProjectName,
                UProjectPath = target.UProjectPath,
                Message = "UnrealEditor.exe was not found for this project."
            };
        }

        var existingPids = _tracker.GetRunningPidsForProject(target.UProjectPath, refresh: true);
        if (existingPids.Count > 0)
        {
            return new UnrealBuildJobSnapshot
            {
                Status = "ready",
                Phase = "ready",
                ProjectName = target.ProjectName,
                UProjectPath = target.UProjectPath,
                EngineVersion = target.EngineVersion,
                EditorPid = existingPids[0],
                Message = "Unreal Editor is already running for this project.",
                OtherEditorsCount = _tracker.GetOtherRunningEditorsCount(target.UProjectPath)
            };
        }

        JobState job;
        lock (_sync)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(UnrealBuildPipeline));
            if (_activeJob != null && !_activeJob.IsTerminal)
                return BuildSnapshotLocked(_activeJob);

            var id = "l_" + (++_jobCounter).ToString("D2");
            job = new JobState(id, target.Clone(), "launch_only", launchAfter: true, forceClose: false, buildBatchPath: string.Empty);
            _jobsById[id] = job;
            _jobOrder.Add(id);
            _activeJob = job;
        }

        _tracker.LockActiveProjectForBuild(target.UProjectPath);
        job.RunTask = Task.Run(() => ExecuteLaunchOnlyAsync(job, serverStopToken), CancellationToken.None);
        return await WaitForJobUpdateAsync(job, waitOnlyForTerminal: true, serverStopToken).ConfigureAwait(false);
    }

    public Dictionary<string, object?> ReadLog(string? jobId, string source, string? search, int tail)
    {
        JobState? job;
        lock (_sync)
        {
            job = ResolveJobLocked(jobId);
        }

        var normalizedSource = string.Equals(source, "editor", StringComparison.OrdinalIgnoreCase) ? "editor" : "build";
        var effectiveTail = Math.Max(1, Math.Min(300, tail <= 0 ? 60 : tail));
        string? logPath = null;

        if (normalizedSource == "build")
        {
            logPath = job?.BuildLogPath;
            if (string.IsNullOrWhiteSpace(logPath) || !File.Exists(logPath))
            {
                logPath = FindLatestFileInDirectory(AppPaths.UnrealBuildLogsDirectory, "*.log");
            }
        }
        else
        {
            logPath = job?.EditorLogPath;
            if (string.IsNullOrWhiteSpace(logPath) || !File.Exists(logPath))
            {
                var activeTarget = job?.Target ?? _tracker.GetActiveTarget(refresh: false);
                if (activeTarget != null && !string.IsNullOrWhiteSpace(activeTarget.ProjectDirectory))
                {
                    var ueLogsDir = Path.Combine(activeTarget.ProjectDirectory, "Saved", "Logs");
                    logPath = FindLatestFileInDirectory(ueLogsDir, "*.log");
                }
            }
        }

        if (string.IsNullOrWhiteSpace(logPath) || !File.Exists(logPath))
        {
            return new Dictionary<string, object?>
            {
                ["found"] = false,
                ["source"] = normalizedSource,
                ["message"] = "No log file is available for source='" + normalizedSource + "'."
            };
        }

        var lines = ReadAllLinesShared(logPath!);
        var totalLines = lines.Count;
        IEnumerable<string> filtered = lines;
        if (!string.IsNullOrWhiteSpace(search))
        {
            var needle = search!.Trim();
            filtered = lines.Where(l => l.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        var matchedList = filtered.ToList();
        var returnedLines = matchedList.Count > effectiveTail
            ? matchedList.Skip(matchedList.Count - effectiveTail).ToList()
            : matchedList;

        return new Dictionary<string, object?>
        {
            ["found"] = true,
            ["job_id"] = job?.JobId,
            ["source"] = normalizedSource,
            ["path"] = logPath,
            ["total_lines"] = totalLines,
            ["matched_lines"] = matchedList.Count,
            ["returned_lines"] = returnedLines.Count,
            ["lines"] = returnedLines
        };
    }

    public void CancelActiveBuild()
    {
        JobState? active;
        lock (_sync)
        {
            active = _activeJob;
        }
        if (active != null && !active.IsTerminal)
            CancelJob(active);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
        }
        CancelActiveBuild();
    }

    // =========================================================================
    // PIPELINE EXECUTION (ZERO HARDCODED BUILD/LAUNCH TIMEOUTS)
    // =========================================================================

    private async Task ExecutePipelineAsync(JobState job, CancellationToken serverStopToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(job.Cancellation.Token, serverStopToken);
        var ct = linked.Token;
        var expectUnrealMcpPort = false;
        var unrealMcpPort = _getUnrealMcpPort();

        try
        {
            // Phase 1: Close ALL running windows of the target .uproject
            SetPhase(job, "closing", "Checking running Unreal Editor instances");
            var targetPids = _tracker.GetRunningPidsForProject(job.Target.UProjectPath, refresh: true);
            if (targetPids.Count > 0)
            {
                if (unrealMcpPort > 0)
                {
                    try
                    {
                        var portOwners = TcpPortInspector.GetListeningProcessIds(unrealMcpPort);
                        expectUnrealMcpPort = targetPids.Any(portOwners.Contains);
                    }
                    catch { }
                }

                var closeResult = await CloseEditorProcessesAsync(job, targetPids, job.ForceClose, ct).ConfigureAwait(false);
                if (!closeResult.Closed)
                {
                    SetTerminal(
                        job,
                        status: "close_blocked",
                        phase: "closing",
                        message: closeResult.Message,
                        blockingPids: closeResult.BlockingPids);
                    return;
                }
            }

            ct.ThrowIfCancellationRequested();

            // Phase 2: Compile with UnrealBuildTool (Build.bat / Rebuild.bat)
            SetPhase(job, "building", "Starting UnrealBuildTool (" + job.Mode + ")");
            var buildResult = await RunUnrealBuildToolAsync(job, ct).ConfigureAwait(false);
            if (buildResult.ExitCode != 0)
            {
                SetTerminal(
                    job,
                    status: "build_failed",
                    phase: "building",
                    exitCode: buildResult.ExitCode,
                    errors: buildResult.Errors,
                    message: "UnrealBuildTool exited with code " + buildResult.ExitCode + ".");
                return;
            }

            ct.ThrowIfCancellationRequested();

            // Phase 3: Launch Unreal Editor (detached from Job Object) and wait for REAL readiness
            if (!job.LaunchAfter)
            {
                SetTerminal(job, status: "ready", phase: "ready", exitCode: 0);
                return;
            }

            await LaunchAndWaitForEditorReadyAsync(job, expectUnrealMcpPort, unrealMcpPort, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            SetTerminal(job, status: "cancelled", phase: job.Phase, message: "Build job was cancelled.");
        }
        catch (Exception ex)
        {
            ErrorLog.Write("UnrealBuildPipeline.ExecutePipelineAsync", ex);
            SetTerminal(job, status: "failed", phase: job.Phase, message: ex.Message);
        }
        finally
        {
            job.TerminateAndDisposeBuildJobObject();
            _tracker.UnlockBuildProject();
        }
    }

    private async Task ExecuteLaunchOnlyAsync(JobState job, CancellationToken serverStopToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(job.Cancellation.Token, serverStopToken);
        var ct = linked.Token;
        try
        {
            await LaunchAndWaitForEditorReadyAsync(job, expectUnrealMcpPort: false, unrealMcpPort: _getUnrealMcpPort(), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            SetTerminal(job, status: "cancelled", phase: job.Phase, message: "Launch was cancelled.");
        }
        catch (Exception ex)
        {
            ErrorLog.Write("UnrealBuildPipeline.ExecuteLaunchOnlyAsync", ex);
            SetTerminal(job, status: "failed", phase: job.Phase, message: ex.Message);
        }
        finally
        {
            _tracker.UnlockBuildProject();
        }
    }

    private async Task<CloseResult> CloseEditorProcessesAsync(JobState? job, List<int> pids, bool forceClose, CancellationToken ct)
    {
        var openProcs = new Dictionary<int, Process>();
        try
        {
            foreach (var pid in pids)
            {
                try
                {
                    var p = Process.GetProcessById(pid);
                    if (!p.HasExited) openProcs[pid] = p;
                    else p.Dispose();
                }
                catch { }
            }

            if (openProcs.Count == 0)
                return new CloseResult(true, null, null);

            if (job != null)
                SetProgress(job, "Closing " + openProcs.Count + " editor window(s)");

            if (forceClose)
            {
                foreach (var kv in openProcs)
                {
                    try { if (!kv.Value.HasExited) kv.Value.Kill(); } catch { }
                }
            }
            else
            {
                foreach (var pid in openProcs.Keys)
                {
                    UnrealEditorTracker.PostCloseToProcessWindows(pid);
                }
            }

            // Event-driven wait until all processes actually exit OR a modal Save dialog blocks closing
            while (true)
            {
                ct.ThrowIfCancellationRequested();

                var alivePids = new List<int>();
                foreach (var kv in openProcs)
                {
                    try
                    {
                        if (!kv.Value.HasExited) alivePids.Add(kv.Key);
                    }
                    catch { }
                }

                if (alivePids.Count == 0)
                    break;

                if (!forceClose)
                {
                    var blocked = new List<int>();
                    string? dialogTitle = null;
                    foreach (var pid in alivePids)
                    {
                        var winState = UnrealEditorTracker.InspectEditorWindows(pid);
                        if (winState.HasModalDialog)
                        {
                            blocked.Add(pid);
                            if (string.IsNullOrWhiteSpace(dialogTitle))
                                dialogTitle = winState.ModalDialogTitle;
                        }
                    }

                    if (blocked.Count > 0)
                    {
                        var titleNote = string.IsNullOrWhiteSpace(dialogTitle) ? string.Empty : " ('" + dialogTitle + "')";
                        return new CloseResult(
                            false,
                            "Editor window blocked closing with a modal dialog" + titleNote +
                            " (likely unsaved assets). Save in Unreal Editor or retry with force_close=true.",
                            blocked);
                    }
                }

                await Task.Delay(300, ct).ConfigureAwait(false);
            }

            // Small settle pause so Windows releases DLL file locks completely after process exit
            await Task.Delay(400, ct).ConfigureAwait(false);
            return new CloseResult(true, null, null);
        }
        finally
        {
            foreach (var p in openProcs.Values)
            {
                try { p.Dispose(); } catch { }
            }
        }
    }

    private async Task<BuildStepResult> RunUnrealBuildToolAsync(JobState job, CancellationToken ct)
    {
        Directory.CreateDirectory(AppPaths.UnrealBuildLogsDirectory);
        RotateBuildLogs();

        var safeProject = Regex.Replace(job.Target.ProjectName, @"[^A-Za-z0-9_-]", "_");
        var logFileName = DateTime.Now.ToString("yyyyMMdd-HHmmss") + "_" + job.JobId + "_" + safeProject + ".log";
        var logPath = Path.Combine(AppPaths.UnrealBuildLogsDirectory, logFileName);
        lock (_sync)
        {
            job.BuildLogPath = logPath;
            job.LogAvailable = true;
        }

        var comSpec = Environment.GetEnvironmentVariable("ComSpec");
        if (string.IsNullOrWhiteSpace(comSpec) || !File.Exists(comSpec))
            comSpec = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");

        // Standard universal UBT invocation for UE 5.1 - 5.9 / 6.x (no deprecated -NoHotReload)
        var innerCmd = "\"" + job.BuildBatchPath + "\" " +
                       job.Target.EditorTarget +
                       " Win64 Development -Project=\"" + job.Target.UProjectPath + "\" -WaitMutex -FromMsBuild";
        var cmdArgs = "/d /c \"" + innerCmd + "\"";

        var startInfo = new ProcessStartInfo
        {
            FileName = comSpec,
            Arguments = cmdArgs,
            WorkingDirectory = job.Target.ProjectDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        var buildJob = new WindowsJobObject("UnrealBuild-" + job.JobId);
        job.AttachBuildJobObject(buildJob, process);

        var exitTcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var logLock = new object();
        using var logWriter = new StreamWriter(
            new FileStream(logPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite),
            new UTF8Encoding(false))
        {
            AutoFlush = true
        };

        void OnLine(string? line)
        {
            if (line == null) return;
            lock (logLock)
            {
                try { logWriter.WriteLine(line); } catch { }
            }
            UpdateProgressFromUbtLine(job, line);
        }

        process.OutputDataReceived += (_, e) => OnLine(e.Data);
        process.ErrorDataReceived += (_, e) => OnLine(e.Data);
        process.Exited += (_, _) =>
        {
            int code = -1;
            try { code = process.ExitCode; } catch { }
            exitTcs.TrySetResult(code);
        };

        using var cancelReg = ct.Register(() =>
        {
            job.TerminateAndDisposeBuildJobObject();
            exitTcs.TrySetCanceled(ct);
        });

        if (!process.Start())
        {
            job.TerminateAndDisposeBuildJobObject();
            throw new InvalidOperationException("Failed to start cmd.exe for UnrealBuildTool.");
        }

        try
        {
            buildJob.Assign(process);
        }
        catch (Exception ex)
        {
            ErrorLog.Write("UnrealBuildPipeline.AssignJobObject", ex);
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        var exitCode = await exitTcs.Task.ConfigureAwait(false);
        // Ensure async output streams finish flushing before reading the log
        try { process.WaitForExit(); } catch { }
        job.TerminateAndDisposeBuildJobObject();

        if (exitCode == 0)
            return new BuildStepResult(0, null);

        var parsedErrors = ParseBuildErrorsFromLog(logPath);
        return new BuildStepResult(exitCode, parsedErrors);
    }

    private async Task LaunchAndWaitForEditorReadyAsync(
        JobState job,
        bool expectUnrealMcpPort,
        int unrealMcpPort,
        CancellationToken ct)
    {
        SetPhase(job, "launching", "Starting UnrealEditor.exe");
        var launchStartedUtc = DateTime.UtcNow;

        // Completely detached from any Job Object & zero inherited handles!
        var editorPid = DetachedProcessLauncher.StartAndGetPid(
            job.Target.EditorExecutable,
            new[] { job.Target.UProjectPath },
            job.Target.ProjectDirectory,
            hideWindow: false,
            breakawayFromJob: true);

        lock (_sync)
        {
            job.EditorPid = editorPid;
        }
        SignalJobUpdated(job);

        Process? editorProcess = null;
        try
        {
            editorProcess = Process.GetProcessById(editorPid);
        }
        catch
        {
            // Already exited immediately
        }

        var ueLogsDir = Path.Combine(job.Target.ProjectDirectory, "Saved", "Logs");
        string? detectedLogPath = null;
        long logReadOffset = 0;

        try
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();

                // 1. Instant crash / premature exit check
                var hasExited = editorProcess == null;
                if (editorProcess != null)
                {
                    try { hasExited = editorProcess.HasExited; }
                    catch { hasExited = true; }
                }

                if (hasExited)
                {
                    var crashLog = FindNewestEditorLogAfter(ueLogsDir, launchStartedUtc) ?? detectedLogPath;
                    lock (_sync)
                    {
                        job.EditorLogPath = crashLog;
                        if (!string.IsNullOrWhiteSpace(crashLog)) job.LogAvailable = true;
                    }
                    var crashSummary = ExtractCrashSummaryFromEditorLog(crashLog);
                    SetTerminal(
                        job,
                        status: "editor_crashed",
                        phase: "launching",
                        errors: crashSummary,
                        message: "UnrealEditor.exe (PID " + editorPid + ") exited unexpectedly during startup.");
                    return;
                }

                // 2. Track real startup progress from newest UE log
                if (detectedLogPath == null)
                    detectedLogPath = FindNewestEditorLogAfter(ueLogsDir, launchStartedUtc);

                if (detectedLogPath != null)
                {
                    lock (_sync)
                    {
                        job.EditorLogPath = detectedLogPath;
                    }
                    UpdateProgressFromEditorLog(job, detectedLogPath, ref logReadOffset);
                }

                // 3. Real Win32 readiness check (no timers!)
                var winState = UnrealEditorTracker.InspectEditorWindows(editorPid);
                if (winState.HasMainUnrealWindow && !winState.HasSplashWindow && winState.IsResponsive)
                {
                    if (!expectUnrealMcpPort || unrealMcpPort <= 0)
                    {
                        _tracker.RefreshNow();
                        SetTerminal(job, status: "ready", phase: "ready", exitCode: 0, editorPid: editorPid);
                        return;
                    }

                    // Project ran Unreal MCP before close -> wait until port is listening again
                    SetProgress(job, "Editor window ready; waiting for Unreal MCP (:" + unrealMcpPort + ")");
                    var listeners = TcpPortInspector.GetListeningProcessIds(unrealMcpPort);
                    if (listeners.Count > 0)
                    {
                        _tracker.RefreshNow();
                        SetTerminal(
                            job,
                            status: "ready",
                            phase: "ready",
                            exitCode: 0,
                            editorPid: editorPid,
                            unrealMcpReady: true);
                        return;
                    }
                }
                else if (winState.HasModalDialog)
                {
                    var note = string.IsNullOrWhiteSpace(winState.ModalDialogTitle)
                        ? "Startup modal dialog open"
                        : "Startup dialog open: " + winState.ModalDialogTitle;
                    SetProgress(job, note);
                }

                await Task.Delay(500, ct).ConfigureAwait(false);
            }
        }
        finally
        {
            try { editorProcess?.Dispose(); } catch { }
        }
    }

    // =========================================================================
    // EVENT-DRIVEN WAITING & LOG PARSING
    // =========================================================================

    private async Task<UnrealBuildJobSnapshot> WaitForJobUpdateAsync(
        JobState job,
        bool waitOnlyForTerminal,
        CancellationToken serverStopToken)
    {
        var initialPhase = job.Phase;
        var deadline = DateTime.UtcNow.AddMilliseconds(HttpKeepAliveWindowMs);

        while (true)
        {
            Task waitTask;
            lock (_sync)
            {
                if (job.IsTerminal)
                    return BuildSnapshotLocked(job);
                if (!waitOnlyForTerminal && !string.Equals(job.Phase, initialPhase, StringComparison.Ordinal))
                    return BuildSnapshotLocked(job);

                var remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.Zero)
                    return BuildSnapshotLocked(job);

                waitTask = job.StateChangedTcs.Task;
            }

            var waitMs = (int)Math.Max(50, Math.Min(HttpKeepAliveWindowMs, (deadline - DateTime.UtcNow).TotalMilliseconds));
            await Task.WhenAny(waitTask, Task.Delay(waitMs, serverStopToken)).ConfigureAwait(false);
            if (serverStopToken.IsCancellationRequested)
            {
                lock (_sync) { return BuildSnapshotLocked(job); }
            }
        }
    }

    private void UpdateProgressFromUbtLine(JobState job, string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        var stepMatch = UbtStepRegex.Match(line);
        if (stepMatch.Success)
        {
            SetProgress(job, "[" + stepMatch.Groups[1].Value + "] " + Truncate(stepMatch.Groups[2].Value.Trim(), 80));
            return;
        }
        if (line.IndexOf("Parsing headers", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            SetProgress(job, "Parsing headers (UHT)");
        }
        else if (line.IndexOf("Reflection code generated", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            SetProgress(job, "UHT reflection generated");
        }
        else if (line.IndexOf("Building ", StringComparison.OrdinalIgnoreCase) >= 0 &&
                 line.IndexOf("action", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            SetProgress(job, Truncate(line.Trim(), 90));
        }
    }

    private void UpdateProgressFromEditorLog(JobState job, string logPath, ref long offset)
    {
        try
        {
            using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length <= offset) return;
            fs.Seek(offset, SeekOrigin.Begin);
            using var reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                if (line.IndexOf("LogShaderCompilers", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    line.IndexOf("Compiling", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    SetProgress(job, "Compiling shaders");
                }
                else if (line.IndexOf("LogLoad: LoadMap:", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    SetProgress(job, "Loading startup map");
                }
                else if (line.IndexOf("Engine Initialization) Total time:", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    SetProgress(job, "Engine initialized; finalizing UI");
                }
            }
            offset = fs.Position;
        }
        catch { }
    }

    private static List<string> ParseBuildErrorsFromLog(string logPath)
    {
        var lines = ReadAllLinesShared(logPath);
        var errors = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var raw in lines)
        {
            var trimmed = raw.Trim();
            if (string.IsNullOrWhiteSpace(trimmed)) continue;
            if (UbtNoiseRegex.IsMatch(trimmed)) continue;

            if (MsvcErrorRegex.IsMatch(trimmed) ||
                ClangErrorRegex.IsMatch(trimmed) ||
                LinkerErrorRegex.IsMatch(trimmed) ||
                UhtErrorRegex.IsMatch(trimmed))
            {
                if (seen.Add(trimmed))
                {
                    errors.Add(trimmed);
                    if (errors.Count >= MaxParsedErrors) break;
                }
            }
        }

        // Universal fallback (e.g. unexpected UBT/UE 6 diagnostic format)
        if (errors.Count == 0)
        {
            var nonEmpty = lines.Select(l => l.Trim()).Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
            errors.AddRange(nonEmpty.Skip(Math.Max(0, nonEmpty.Count - MaxParsedErrors)));
        }

        return errors;
    }

    private static List<string> ExtractCrashSummaryFromEditorLog(string? logPath)
    {
        var result = new List<string>();
        if (string.IsNullOrWhiteSpace(logPath) || !File.Exists(logPath))
            return result;

        var lines = ReadAllLinesShared(logPath!);
        var fatalIdx = -1;
        for (var i = lines.Count - 1; i >= 0; i--)
        {
            var line = lines[i];
            if (line.IndexOf("Fatal error", StringComparison.OrdinalIgnoreCase) >= 0 ||
                line.IndexOf("Assertion failed", StringComparison.OrdinalIgnoreCase) >= 0 ||
                line.IndexOf("Unhandled Exception", StringComparison.OrdinalIgnoreCase) >= 0 ||
                line.IndexOf("Ensure condition failed", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                fatalIdx = i;
                break;
            }
        }

        if (fatalIdx >= 0)
        {
            var end = Math.Min(lines.Count, fatalIdx + 20);
            for (var i = fatalIdx; i < end; i++)
            {
                var trimmed = lines[i].Trim();
                if (!string.IsNullOrWhiteSpace(trimmed))
                    result.Add(trimmed);
            }
            return result;
        }

        var tail = lines.Select(l => l.Trim()).Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
        return tail.Skip(Math.Max(0, tail.Count - 20)).ToList();
    }

    private static string? FindNewestEditorLogAfter(string logsDir, DateTime thresholdUtc)
    {
        try
        {
            if (!Directory.Exists(logsDir)) return null;
            var cutoff = thresholdUtc.AddSeconds(-2);
            return new DirectoryInfo(logsDir)
                .GetFiles("*.log", SearchOption.TopDirectoryOnly)
                .Where(f => f.LastWriteTimeUtc >= cutoff || f.CreationTimeUtc >= cutoff)
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .Select(f => f.FullName)
                .FirstOrDefault();
        }
        catch { return null; }
    }

    private static string? FindLatestFileInDirectory(string dir, string pattern)
    {
        try
        {
            if (!Directory.Exists(dir)) return null;
            return new DirectoryInfo(dir)
                .GetFiles(pattern, SearchOption.TopDirectoryOnly)
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .Select(f => f.FullName)
                .FirstOrDefault();
        }
        catch { return null; }
    }

    private static void RotateBuildLogs()
    {
        try
        {
            if (!Directory.Exists(AppPaths.UnrealBuildLogsDirectory)) return;
            var files = new DirectoryInfo(AppPaths.UnrealBuildLogsDirectory)
                .GetFiles("*.log", SearchOption.TopDirectoryOnly)
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .ToList();
            for (var i = MaxStoredBuildLogs - 1; i < files.Count; i++)
            {
                try { files[i].Delete(); } catch { }
            }
        }
        catch { }
    }

    private static List<string> ReadAllLinesShared(string path)
    {
        var result = new List<string>();
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            string? line;
            while ((line = reader.ReadLine()) != null)
                result.Add(line);
        }
        catch { }
        return result;
    }

    private void SetPhase(JobState job, string phase, string? progress = null)
    {
        lock (_sync)
        {
            job.Phase = phase;
            if (progress != null) job.Progress = progress;
        }
        SignalJobUpdated(job);
    }

    private void SetProgress(JobState job, string progress)
    {
        lock (_sync)
        {
            job.Progress = progress;
        }
    }

    private void SetTerminal(
        JobState job,
        string status,
        string phase,
        int? exitCode = null,
        int? editorPid = null,
        bool? unrealMcpReady = null,
        List<int>? blockingPids = null,
        List<string>? errors = null,
        string? message = null)
    {
        lock (_sync)
        {
            if (job.IsTerminal) return;
            job.Status = status;
            job.Phase = phase;
            job.ExitCode = exitCode ?? job.ExitCode;
            job.EditorPid = editorPid ?? job.EditorPid;
            job.UnrealMcpReady = unrealMcpReady ?? job.UnrealMcpReady;
            job.BlockingPids = blockingPids;
            job.Errors = errors;
            job.Message = message;
            job.CompletedUtc = DateTime.UtcNow;
            if (ReferenceEquals(_activeJob, job))
                _activeJob = null;
        }
        SignalJobUpdated(job);
    }

    private void SignalJobUpdated(JobState job)
    {
        TaskCompletionSource<bool> previous;
        lock (_sync)
        {
            previous = job.StateChangedTcs;
            job.StateChangedTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        previous.TrySetResult(true);
    }

    private void CancelJob(JobState job)
    {
        try { job.Cancellation.Cancel(); } catch { }
        job.TerminateAndDisposeBuildJobObject();
    }

    private JobState? ResolveJobLocked(string? jobId)
    {
        if (!string.IsNullOrWhiteSpace(jobId) && _jobsById.TryGetValue(jobId!.Trim(), out var exact))
            return exact;
        if (_activeJob != null) return _activeJob;
        if (_jobOrder.Count > 0 && _jobsById.TryGetValue(_jobOrder[_jobOrder.Count - 1], out var latest))
            return latest;
        return null;
    }

    private UnrealBuildJobSnapshot BuildSnapshotLocked(JobState job)
    {
        var endUtc = job.CompletedUtc ?? DateTime.UtcNow;
        var elapsed = Math.Round(Math.Max(0, (endUtc - job.StartedUtc).TotalSeconds), 1);
        return new UnrealBuildJobSnapshot
        {
            JobId = job.JobId,
            Status = job.Status,
            Phase = job.Phase,
            Progress = job.Progress,
            ProjectName = job.Target.ProjectName,
            UProjectPath = job.Target.UProjectPath,
            EngineVersion = job.Target.EngineVersion,
            Mode = job.Mode,
            LaunchAfter = job.LaunchAfter,
            ElapsedSeconds = elapsed,
            ExitCode = job.ExitCode,
            EditorPid = job.EditorPid,
            UnrealMcpReady = job.UnrealMcpReady,
            BlockingPids = job.BlockingPids != null ? new List<int>(job.BlockingPids) : null,
            Message = job.Message,
            Errors = job.Errors != null ? new List<string>(job.Errors) : null,
            LogAvailable = job.LogAvailable,
            BuildLogPath = job.BuildLogPath,
            EditorLogPath = job.EditorLogPath,
            OtherEditorsCount = _tracker.GetOtherRunningEditorsCount(job.Target.UProjectPath)
        };
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s.Substring(0, max - 1) + "…";

    private sealed class CloseResult
    {
        public CloseResult(bool closed, string? message, List<int>? blockingPids)
        {
            Closed = closed;
            Message = message;
            BlockingPids = blockingPids;
        }
        public bool Closed { get; }
        public string? Message { get; }
        public List<int>? BlockingPids { get; }
    }

    private sealed class BuildStepResult
    {
        public BuildStepResult(int exitCode, List<string>? errors)
        {
            ExitCode = exitCode;
            Errors = errors;
        }
        public int ExitCode { get; }
        public List<string>? Errors { get; }
    }

    private sealed class JobState
    {
        private readonly object _procLock = new();
        private WindowsJobObject? _buildJobObject;
        private Process? _buildProcess;

        public JobState(string jobId, UnrealProjectTarget target, string mode, bool launchAfter, bool forceClose, string buildBatchPath)
        {
            JobId = jobId;
            Target = target;
            Mode = mode;
            LaunchAfter = launchAfter;
            ForceClose = forceClose;
            BuildBatchPath = buildBatchPath;
            StartedUtc = DateTime.UtcNow;
        }

        public string JobId { get; }
        public UnrealProjectTarget Target { get; }
        public string Mode { get; }
        public bool LaunchAfter { get; }
        public bool ForceClose { get; }
        public string BuildBatchPath { get; }
        public DateTime StartedUtc { get; }
        public DateTime? CompletedUtc { get; set; }
        public string Status { get; set; } = "in_progress";
        public string Phase { get; set; } = "initializing";
        public string? Progress { get; set; }
        public int? ExitCode { get; set; }
        public int? EditorPid { get; set; }
        public bool? UnrealMcpReady { get; set; }
        public List<int>? BlockingPids { get; set; }
        public string? Message { get; set; }
        public List<string>? Errors { get; set; }
        public bool LogAvailable { get; set; }
        public string? BuildLogPath { get; set; }
        public string? EditorLogPath { get; set; }
        public CancellationTokenSource Cancellation { get; } = new();
        public TaskCompletionSource<bool> StateChangedTcs { get; set; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task? RunTask { get; set; }

        public bool IsTerminal => Status is "ready" or "build_failed" or "editor_crashed" or "close_blocked" or "no_cpp_target" or "cancelled" or "failed";

        public void AttachBuildJobObject(WindowsJobObject jobObj, Process process)
        {
            lock (_procLock)
            {
                _buildJobObject = jobObj;
                _buildProcess = process;
            }
        }

        public void TerminateAndDisposeBuildJobObject()
        {
            WindowsJobObject? jobObj;
            Process? proc;
            lock (_procLock)
            {
                jobObj = _buildJobObject;
                proc = _buildProcess;
                _buildJobObject = null;
                _buildProcess = null;
            }

            if (proc != null)
            {
                try
                {
                    if (!proc.HasExited)
                        ProcessTreeTerminator.TerminateDescendants(proc.Id, "UnrealBuild-" + JobId);
                }
                catch { }
            }

            if (jobObj != null)
            {
                try { jobObj.TryTerminateAll(out _); } catch { }
                try { jobObj.Dispose(); } catch { }
            }

            if (proc != null)
            {
                try { proc.Dispose(); } catch { }
            }
        }
    }
}
