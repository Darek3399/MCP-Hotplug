using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace McpHotplug.Services;

/// <summary>
/// Built-in local loopback MCP server for closing, building (UBT), and relaunching
/// Unreal Engine projects (UE 5.1-5.9 / 6.x) without relying on an IDE or external runtime.
/// Runs inside MCPHotplug.exe on 127.0.0.1:8006/mcp.
/// </summary>
internal sealed class UnrealBuildMcpServer : IDisposable
{
    private const string ProtocolVersion = "2025-06-18";
    private const int MaxBodyBytes = 4 * 1024 * 1024;
    private const int MaxHeaderBytes = 64 * 1024;

    private static readonly UTF8Encoding Utf8NoBom = new(false);

    private readonly int _port;
    private readonly UnrealEditorTracker _tracker;
    private readonly UnrealBuildPipeline _pipeline;
    private readonly object _sync = new();
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoopTask;
    private bool _disposed;

    public UnrealBuildMcpServer(int port, Func<int> getUnrealMcpPort)
    {
        _port = port;
        _tracker = new UnrealEditorTracker();
        _pipeline = new UnrealBuildPipeline(_tracker, getUnrealMcpPort);
    }

    public bool IsRunning
    {
        get
        {
            lock (_sync)
            {
                return !_disposed && _listener != null;
            }
        }
    }

    public void Start()
    {
        lock (_sync)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(UnrealBuildMcpServer));
            if (_listener != null) return;

            var listener = new TcpListener(IPAddress.Loopback, _port);
            TcpPortInspector.DisableHandleInheritance(listener.Server.Handle);
            listener.Server.ExclusiveAddressUse = true;
            listener.Start();

            _listener = listener;
            _cts = new CancellationTokenSource();
            _tracker.Start();
            _acceptLoopTask = Task.Run(() => AcceptLoopAsync(listener, _cts.Token), CancellationToken.None);
        }
    }

    public void Stop()
    {
        TcpListener? listener;
        CancellationTokenSource? cts;
        Task? acceptTask;

        lock (_sync)
        {
            listener = _listener;
            cts = _cts;
            acceptTask = _acceptLoopTask;
            _listener = null;
            _cts = null;
            _acceptLoopTask = null;
        }

        _pipeline.CancelActiveBuild();
        _tracker.Stop();

        try { cts?.Cancel(); } catch { }
        try { listener?.Stop(); } catch { }
        if (acceptTask != null)
        {
            try { acceptTask.Wait(1500); } catch { }
        }
        try { cts?.Dispose(); } catch { }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
        }
        Stop();
        _pipeline.Dispose();
        _tracker.Dispose();
    }

    // =========================================================================
    // LIGHTWEIGHT LOOPBACK HTTP SERVER (ZERO URLACL / ADMIN REQUIREMENTS)
    // =========================================================================

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException)
            {
                if (ct.IsCancellationRequested) break;
                continue;
            }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                    ErrorLog.Write("UnrealBuildMcpServer.AcceptLoop", ex);
                break;
            }

            _ = Task.Run(() => HandleClientAsync(client, ct), CancellationToken.None);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            try
            {
                client.NoDelay = true;
                using var stream = client.GetStream();
                var request = await ReadHttpRequestAsync(stream, ct).ConfigureAwait(false);
                if (request == null) return;

                var path = StripQuery(request.Path);
                if (string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(path, "/__manager/health", StringComparison.Ordinal))
                {
                    await WriteJsonResponseAsync(stream, 200, "OK", new Dictionary<string, object?>
                    {
                        ["status"] = "ok",
                        ["service"] = "Unreal Build MCP"
                    }, null).ConfigureAwait(false);
                    return;
                }

                if (!string.Equals(path, "/mcp", StringComparison.Ordinal))
                {
                    await WriteJsonResponseAsync(stream, 404, "Not Found", new Dictionary<string, object?>
                    {
                        ["error"] = "Not found."
                    }, null).ConfigureAwait(false);
                    return;
                }

                if (string.Equals(request.Method, "DELETE", StringComparison.OrdinalIgnoreCase))
                {
                    await WriteJsonResponseAsync(stream, 200, "OK", new Dictionary<string, object?>
                    {
                        ["ok"] = true
                    }, null).ConfigureAwait(false);
                    return;
                }

                if (!string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
                {
                    await WriteEmptyResponseAsync(stream, 405, "Method Not Allowed", "Allow: POST, DELETE\r\n").ConfigureAwait(false);
                    return;
                }

                IDictionary<string, object?>? rpc;
                try
                {
                    rpc = McpServerConfigParser.DeserializeJson(request.Body) as IDictionary<string, object?>;
                }
                catch
                {
                    await WriteJsonResponseAsync(stream, 400, "Bad Request", BuildRpcError(null, -32700, "Parse error."), null).ConfigureAwait(false);
                    return;
                }

                if (rpc == null ||
                    !string.Equals(GetString(rpc, "jsonrpc"), "2.0", StringComparison.Ordinal) ||
                    string.IsNullOrWhiteSpace(GetString(rpc, "method")))
                {
                    object? badId = null;
                    rpc?.TryGetValue("id", out badId);
                    await WriteJsonResponseAsync(stream, 400, "Bad Request", BuildRpcError(badId, -32600, "Invalid Request."), null).ConfigureAwait(false);
                    return;
                }

                if (!rpc.TryGetValue("id", out var rpcId) || rpcId == null)
                {
                    await WriteEmptyResponseAsync(stream, 202, "Accepted", null).ConfigureAwait(false);
                    return;
                }

                var sessionId = request.Headers.TryGetValue("mcp-session-id", out var sid) && !string.IsNullOrWhiteSpace(sid)
                    ? sid
                    : "unreal-build-mcp-session";

                var method = GetString(rpc, "method")!;
                object responsePayload;

                switch (method)
                {
                    case "initialize":
                        responsePayload = BuildRpcResult(rpcId, new Dictionary<string, object?>
                        {
                            ["protocolVersion"] = ProtocolVersion,
                            ["capabilities"] = new Dictionary<string, object?>
                            {
                                ["tools"] = new Dictionary<string, object?>()
                            },
                            ["serverInfo"] = new Dictionary<string, object?>
                            {
                                ["name"] = "Unreal Build MCP",
                                ["version"] = "1.0.0"
                            }
                        });
                        break;

                    case "ping":
                        responsePayload = BuildRpcResult(rpcId, new Dictionary<string, object?>());
                        break;

                    case "tools/list":
                        responsePayload = BuildRpcResult(rpcId, new Dictionary<string, object?>
                        {
                            ["tools"] = BuildToolDefinitions()
                        });
                        break;

                    case "tools/call":
                        var callParams = rpc.TryGetValue("params", out var rawParams)
                            ? rawParams as IDictionary<string, object?>
                            : null;
                        var toolResult = await HandleToolCallAsync(callParams, ct).ConfigureAwait(false);
                        responsePayload = BuildRpcResult(rpcId, toolResult);
                        break;

                    default:
                        responsePayload = BuildRpcError(rpcId, -32601, "Method not found: " + method);
                        break;
                }

                await WriteJsonResponseAsync(stream, 200, "OK", responsePayload, sessionId).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
            catch (SocketException) { }
            catch (Exception ex)
            {
                ErrorLog.Write("UnrealBuildMcpServer.HandleClient", ex);
            }
        }
    }

    // =========================================================================
    // MCP TOOL SCHEMAS & DISPATCH
    // =========================================================================

    private static List<object> BuildToolDefinitions()
    {
        return new List<object>
        {
            new Dictionary<string, object?>
            {
                ["name"] = "rebuild_project",
                ["description"] =
                    "Close all Unreal Editor windows for the target project, compile C++ with UnrealBuildTool (UE 5.1-5.9 / 6.x), " +
                    "and relaunch the editor until it is actually ready. " +
                    "CRITICAL PREREQUISITES: Before calling this tool, via Unreal MCP you MUST: " +
                    "(1) stop PIE if running; " +
                    "(2) compile Blueprints and save all dirty levels and content assets to disk so no unsaved changes are lost and no Save dialog blocks closing; " +
                    "(3) ONLY notify the user about Blueprint compile warnings/errors if they actually prevent saving or block cleanly closing the editor (risking data loss) — " +
                    "if all dirty packages save cleanly and the editor can be closed, rebuilt, and reopened without losing data, ignore non-blocking Blueprint warnings/errors and do not mention them in the report. " +
                    "When status='ready', DO NOT call get_build_log — logs are strictly for diagnosing failures. " +
                    "When status='in_progress', call get_build_status with the returned job_id until a terminal status " +
                    "('ready', 'build_failed', 'editor_crashed', 'close_blocked', 'no_cpp_target', 'cancelled'). " +
                    "Use mode='incremental' by default; use mode='rebuild' only if Intermediate/UHT artifacts are broken.",
                ["inputSchema"] = new Dictionary<string, object?>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object?>
                    {
                        ["mode"] = new Dictionary<string, object?>
                        {
                            ["type"] = "string",
                            ["enum"] = new[] { "incremental", "rebuild" },
                            ["description"] = "Build mode: 'incremental' (Build.bat, default) or 'rebuild' (Rebuild.bat)."
                        },
                        ["launch_after"] = new Dictionary<string, object?>
                        {
                            ["type"] = "boolean",
                            ["description"] = "Relaunch Unreal Editor after a successful build and wait until ready (default: true)."
                        },
                        ["force_close"] = new Dictionary<string, object?>
                        {
                            ["type"] = "boolean",
                            ["description"] = "Force-kill editor processes instead of graceful WM_CLOSE. Use only after close_blocked and confirming no unsaved work remains (default: false)."
                        },
                        ["project"] = new Dictionary<string, object?>
                        {
                            ["type"] = "string",
                            ["description"] = "Optional project name or .uproject path. Omit to use the active/auto-detected project."
                        }
                    },
                    ["additionalProperties"] = false
                }
            },
            new Dictionary<string, object?>
            {
                ["name"] = "get_build_status",
                ["description"] =
                    "Wait event-driven for the next phase change or completion of an active Unreal build/relaunch job, or inspect the latest job. " +
                    "Pass cancel=true to abort an active compilation (immediately kills the UBT/compiler process tree without affecting Unreal Editor). " +
                    "Never call get_build_log when status='ready'.",
                ["inputSchema"] = new Dictionary<string, object?>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object?>
                    {
                        ["job_id"] = new Dictionary<string, object?>
                        {
                            ["type"] = "string",
                            ["description"] = "Optional job_id returned by rebuild_project. Defaults to the active or most recent job."
                        },
                        ["cancel"] = new Dictionary<string, object?>
                        {
                            ["type"] = "boolean",
                            ["description"] = "Set true to cancel the active build job (default: false)."
                        }
                    },
                    ["additionalProperties"] = false
                }
            },
            new Dictionary<string, object?>
            {
                ["name"] = "get_build_log",
                ["description"] =
                    "Read filtered lines from a failed build log ('build') or Unreal Editor launch/crash log ('editor'). " +
                    "Call ONLY when the compact errors returned by rebuild_project/get_build_status are insufficient to diagnose a failure. " +
                    "Never call after a successful build.",
                ["inputSchema"] = new Dictionary<string, object?>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object?>
                    {
                        ["job_id"] = new Dictionary<string, object?>
                        {
                            ["type"] = "string",
                            ["description"] = "Optional job_id. Defaults to the most recent job."
                        },
                        ["source"] = new Dictionary<string, object?>
                        {
                            ["type"] = "string",
                            ["enum"] = new[] { "build", "editor" },
                            ["description"] = "Log source: 'build' (UBT compiler output, default) or 'editor' (newest UE Saved/Logs file)."
                        },
                        ["search"] = new Dictionary<string, object?>
                        {
                            ["type"] = "string",
                            ["description"] = "Optional case-insensitive substring filter (e.g. file name, symbol, or error code)."
                        },
                        ["tail"] = new Dictionary<string, object?>
                        {
                            ["type"] = "integer",
                            ["minimum"] = 1,
                            ["maximum"] = 300,
                            ["description"] = "Maximum trailing lines to return (default: 60, max: 300)."
                        }
                    },
                    ["additionalProperties"] = false
                }
            },
            new Dictionary<string, object?>
            {
                ["name"] = "unreal_editors",
                ["description"] =
                    "Inspect and manage running Unreal Editor instances and the active build target project. " +
                    "Actions: 'list' (show running editors and active target), 'select' (pin target by project name, .uproject path, or pid), " +
                    "'close' (gracefully close all editor windows of target project — BEFORE calling 'close', via Unreal MCP stop PIE, compile Blueprints, and save all dirty levels/assets; only report Blueprint warnings/errors if they block saving or closing), " +
                    "'launch' (launch target project and wait until editor is ready).",
                ["inputSchema"] = new Dictionary<string, object?>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object?>
                    {
                        ["action"] = new Dictionary<string, object?>
                        {
                            ["type"] = "string",
                            ["enum"] = new[] { "list", "select", "close", "launch" },
                            ["description"] = "Operation to perform."
                        },
                        ["project"] = new Dictionary<string, object?>
                        {
                            ["type"] = "string",
                            ["description"] = "Optional project name or .uproject path."
                        },
                        ["pid"] = new Dictionary<string, object?>
                        {
                            ["type"] = "integer",
                            ["description"] = "Optional UnrealEditor.exe PID (useful with 'select' when multiple editors are open)."
                        },
                        ["force"] = new Dictionary<string, object?>
                        {
                            ["type"] = "boolean",
                            ["description"] = "Force-kill instead of graceful WM_CLOSE when action='close' (default: false)."
                        }
                    },
                    ["required"] = new[] { "action" },
                    ["additionalProperties"] = false
                }
            }
        };
    }

    private async Task<Dictionary<string, object?>> HandleToolCallAsync(IDictionary<string, object?>? callParams, CancellationToken ct)
    {
        var toolName = callParams != null ? GetString(callParams, "name") ?? string.Empty : string.Empty;
        var args = callParams != null && callParams.TryGetValue("arguments", out var rawArgs)
            ? rawArgs as IDictionary<string, object?> ?? new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

        try
        {
            Dictionary<string, object?> payload = toolName switch
            {
                "rebuild_project" => await ToolRebuildProjectAsync(args, ct).ConfigureAwait(false),
                "get_build_status" => await ToolGetBuildStatusAsync(args, ct).ConfigureAwait(false),
                "get_build_log" => ToolGetBuildLog(args),
                "unreal_editors" => await ToolUnrealEditorsAsync(args, ct).ConfigureAwait(false),
                _ => throw new InvalidOperationException("Unknown Unreal Build MCP tool: " + toolName)
            };

            return new Dictionary<string, object?>
            {
                ["content"] = new object[]
                {
                    new Dictionary<string, object?>
                    {
                        ["type"] = "text",
                        ["text"] = McpServerConfigParser.SerializeJson(payload)
                    }
                },
                ["structuredContent"] = payload
            };
        }
        catch (Exception ex)
        {
            return new Dictionary<string, object?>
            {
                ["isError"] = true,
                ["content"] = new object[]
                {
                    new Dictionary<string, object?>
                    {
                        ["type"] = "text",
                        ["text"] = ex.Message
                    }
                }
            };
        }
    }

    private async Task<Dictionary<string, object?>> ToolRebuildProjectAsync(IDictionary<string, object?> args, CancellationToken ct)
    {
        var mode = GetString(args, "mode") ?? "incremental";
        var launchAfter = GetBool(args, "launch_after", defaultValue: true);
        var forceClose = GetBool(args, "force_close", defaultValue: false);
        var projectSelector = GetString(args, "project");

        var target = _tracker.ResolveProjectTarget(projectSelector, pid: null, pinAsActive: !string.IsNullOrWhiteSpace(projectSelector));
        if (target == null)
        {
            throw new InvalidOperationException(
                "No Unreal Engine project is currently running or selected. " +
                "Open a project in Unreal Editor or pass its .uproject path via the 'project' parameter.");
        }

        var snapshot = await _pipeline.StartRebuildAsync(target, mode, launchAfter, forceClose, ct).ConfigureAwait(false);
        return FormatJobSnapshot(snapshot);
    }

    private async Task<Dictionary<string, object?>> ToolGetBuildStatusAsync(IDictionary<string, object?> args, CancellationToken ct)
    {
        var jobId = GetString(args, "job_id");
        var cancel = GetBool(args, "cancel", defaultValue: false);

        var snapshot = await _pipeline.GetStatusAsync(jobId, cancel, ct).ConfigureAwait(false);
        if (snapshot == null)
        {
            return new Dictionary<string, object?>
            {
                ["status"] = "idle",
                ["message"] = "No build jobs have been started in this session."
            };
        }

        return FormatJobSnapshot(snapshot);
    }

    private Dictionary<string, object?> ToolGetBuildLog(IDictionary<string, object?> args)
    {
        var jobId = GetString(args, "job_id");
        var source = GetString(args, "source") ?? "build";
        var search = GetString(args, "search");
        var tail = GetInt(args, "tail") ?? 60;
        return _pipeline.ReadLog(jobId, source, search, tail);
    }

    private async Task<Dictionary<string, object?>> ToolUnrealEditorsAsync(IDictionary<string, object?> args, CancellationToken ct)
    {
        var action = (GetString(args, "action") ?? string.Empty).Trim().ToLowerInvariant();
        var projectSelector = GetString(args, "project");
        var pid = GetInt(args, "pid");
        var force = GetBool(args, "force", defaultValue: false);

        switch (action)
        {
            case "list":
                return BuildEditorsListPayload();

            case "select":
                if (string.IsNullOrWhiteSpace(projectSelector) && !pid.HasValue)
                    throw new InvalidOperationException("Provide 'project' (name or .uproject path) or 'pid' for action='select'.");

                var selected = _tracker.ResolveProjectTarget(projectSelector, pid, pinAsActive: true);
                if (selected == null)
                    throw new InvalidOperationException("Could not find a matching Unreal project or running editor PID.");

                return new Dictionary<string, object?>
                {
                    ["selected"] = FormatProjectTarget(selected, _tracker.GetRunningPidsForProject(selected.UProjectPath, refresh: false))
                };

            case "close":
                var closeTarget = _tracker.ResolveProjectTarget(projectSelector, pid, pinAsActive: false);
                if (closeTarget == null)
                    throw new InvalidOperationException("No active or matching Unreal project found to close.");

                return await _pipeline.CloseEditorsOnlyAsync(closeTarget, force, ct).ConfigureAwait(false);

            case "launch":
                var launchTarget = _tracker.ResolveProjectTarget(projectSelector, pid, pinAsActive: !string.IsNullOrWhiteSpace(projectSelector));
                if (launchTarget == null)
                    throw new InvalidOperationException("No active or matching Unreal project found to launch.");

                var launchSnap = await _pipeline.LaunchEditorOnlyAsync(launchTarget, ct).ConfigureAwait(false);
                return FormatJobSnapshot(launchSnap);

            default:
                throw new InvalidOperationException("Unsupported action '" + action + "'. Use 'list', 'select', 'close', or 'launch'.");
        }
    }

    private Dictionary<string, object?> BuildEditorsListPayload()
    {
        var running = _tracker.GetRunningEditors(refresh: true);
        var active = _tracker.GetActiveTarget(refresh: false);

        var editorsArray = running.Select(e => (object)new Dictionary<string, object?>
        {
            ["pid"] = e.ProcessId,
            ["project"] = e.ProjectName,
            ["uproject"] = e.UProjectPath,
            ["engine_version"] = e.EngineVersion,
            ["active"] = active != null && string.Equals(active.UProjectPath, e.UProjectPath, StringComparison.OrdinalIgnoreCase)
        }).ToList();

        var result = new Dictionary<string, object?>
        {
            ["running_count"] = editorsArray.Count,
            ["editors"] = editorsArray
        };

        if (active != null)
        {
            result["active_target"] = FormatProjectTarget(
                active,
                _tracker.GetRunningPidsForProject(active.UProjectPath, refresh: false));
        }

        return result;
    }

    // =========================================================================
    // TOKEN-MINIMAL PAYLOAD FORMATTING
    // =========================================================================

    private static Dictionary<string, object?> FormatProjectTarget(UnrealProjectTarget target, List<int> runningPids)
    {
        var dict = new Dictionary<string, object?>
        {
            ["project"] = target.ProjectName,
            ["uproject"] = target.UProjectPath,
            ["running"] = runningPids.Count > 0,
            ["pids"] = runningPids,
            ["is_cpp"] = target.IsCppProject
        };
        if (!string.IsNullOrWhiteSpace(target.EngineVersion)) dict["engine_version"] = target.EngineVersion;
        if (!string.IsNullOrWhiteSpace(target.EditorTarget)) dict["editor_target"] = target.EditorTarget;
        return dict;
    }

    private static Dictionary<string, object?> FormatJobSnapshot(UnrealBuildJobSnapshot snap)
    {
        // On success: ultra-compact response, ZERO log clutter
        if (string.Equals(snap.Status, "ready", StringComparison.Ordinal))
        {
            var ok = new Dictionary<string, object?>
            {
                ["status"] = "ready",
                ["project"] = snap.ProjectName,
                ["duration_sec"] = snap.ElapsedSeconds
            };
            if (snap.EditorPid.HasValue) ok["editor_pid"] = snap.EditorPid.Value;
            if (snap.UnrealMcpReady.HasValue) ok["unreal_mcp_ready"] = snap.UnrealMcpReady.Value;
            if (snap.OtherEditorsCount > 0) ok["other_editors_count"] = snap.OtherEditorsCount;
            if (!string.IsNullOrWhiteSpace(snap.Message)) ok["message"] = snap.Message;
            return ok;
        }

        if (string.Equals(snap.Status, "in_progress", StringComparison.Ordinal))
        {
            var prog = new Dictionary<string, object?>
            {
                ["status"] = "in_progress",
                ["job_id"] = snap.JobId,
                ["project"] = snap.ProjectName,
                ["phase"] = snap.Phase,
                ["elapsed_sec"] = snap.ElapsedSeconds
            };
            if (!string.IsNullOrWhiteSpace(snap.Progress)) prog["progress"] = snap.Progress;
            return prog;
        }

        // Failure / blocked / cancelled: compact diagnostics only
        var err = new Dictionary<string, object?>
        {
            ["status"] = snap.Status,
            ["project"] = snap.ProjectName,
            ["phase"] = snap.Phase,
            ["duration_sec"] = snap.ElapsedSeconds
        };
        if (!string.IsNullOrWhiteSpace(snap.JobId)) err["job_id"] = snap.JobId;
        if (snap.ExitCode.HasValue) err["exit_code"] = snap.ExitCode.Value;
        if (snap.BlockingPids != null && snap.BlockingPids.Count > 0) err["blocking_pids"] = snap.BlockingPids;
        if (!string.IsNullOrWhiteSpace(snap.Message)) err["message"] = snap.Message;
        if (snap.Errors != null && snap.Errors.Count > 0)
        {
            err["error_count"] = snap.Errors.Count;
            err["errors"] = snap.Errors;
        }
        if (snap.LogAvailable) err["log_available"] = true;
        if (snap.OtherEditorsCount > 0) err["other_editors_count"] = snap.OtherEditorsCount;
        return err;
    }

    // =========================================================================
    // RAW HTTP/1.1 FRAMING HELPERS
    // =========================================================================

    private static async Task<HttpRequestData?> ReadHttpRequestAsync(NetworkStream stream, CancellationToken ct)
    {
        var buffer = new byte[8192];
        using var headerMem = new MemoryStream();
        var headerEndIndex = -1;

        while (headerEndIndex < 0)
        {
            var read = await stream.ReadAsync(buffer, 0, buffer.Length, ct).ConfigureAwait(false);
            if (read == 0) return null;
            headerMem.Write(buffer, 0, read);
            if (headerMem.Length > MaxHeaderBytes)
                throw new InvalidOperationException("HTTP headers too large.");

            headerEndIndex = FindHeaderDelimiter(headerMem.GetBuffer(), (int)headerMem.Length);
        }

        var rawBuf = headerMem.GetBuffer();
        var totalBuffered = (int)headerMem.Length;
        var headerText = Encoding.ASCII.GetString(rawBuf, 0, headerEndIndex);
        var lines = headerText.Split(new[] { "\r\n" }, StringSplitOptions.None);
        if (lines.Length == 0) return null;

        var requestLine = lines[0].Split(' ');
        if (requestLine.Length < 2) return null;
        var method = requestLine[0].Trim();
        var path = requestLine[1].Trim();

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 1; i < lines.Length; i++)
        {
            var colon = lines[i].IndexOf(':');
            if (colon <= 0) continue;
            headers[lines[i].Substring(0, colon).Trim()] = lines[i].Substring(colon + 1).Trim();
        }

        var bodyStart = headerEndIndex + 4;
        var alreadyReadBodyLen = totalBuffered - bodyStart;

        using var bodyMem = new MemoryStream();
        if (alreadyReadBodyLen > 0)
            bodyMem.Write(rawBuf, bodyStart, alreadyReadBodyLen);

        var isChunked = headers.TryGetValue("transfer-encoding", out var te) &&
                        te.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0;

        string bodyText;
        if (isChunked)
        {
            bodyText = await ReadChunkedBodyAsync(stream, bodyMem, ct).ConfigureAwait(false);
        }
        else
        {
            var contentLength = 0;
            if (headers.TryGetValue("content-length", out var clRaw) && int.TryParse(clRaw, out var parsedLen) && parsedLen > 0)
                contentLength = parsedLen;

            if (contentLength > MaxBodyBytes)
                throw new InvalidOperationException("Request payload too large.");

            while (bodyMem.Length < contentLength)
            {
                var remaining = contentLength - (int)bodyMem.Length;
                var toRead = Math.Min(buffer.Length, remaining);
                var read = await stream.ReadAsync(buffer, 0, toRead, ct).ConfigureAwait(false);
                if (read == 0) break;
                bodyMem.Write(buffer, 0, read);
            }
            bodyText = Utf8NoBom.GetString(bodyMem.GetBuffer(), 0, (int)bodyMem.Length);
        }

        return new HttpRequestData(method, path, headers, bodyText);
    }

    private static async Task<string> ReadChunkedBodyAsync(NetworkStream stream, MemoryStream initialBuffer, CancellationToken ct)
    {
        var pending = initialBuffer.ToArray();
        var pos = 0;
        using var decoded = new MemoryStream();
        var temp = new byte[4096];

        async Task EnsureBytesAsync(int needed)
        {
            while (pending.Length - pos < needed)
            {
                var read = await stream.ReadAsync(temp, 0, temp.Length, ct).ConfigureAwait(false);
                if (read == 0) throw new EndOfStreamException();
                var rem = pending.Length - pos;
                var next = new byte[rem + read];
                Buffer.BlockCopy(pending, pos, next, 0, rem);
                Buffer.BlockCopy(temp, 0, next, rem, read);
                pending = next;
                pos = 0;
            }
        }

        async Task<string> ReadLineAsync()
        {
            while (true)
            {
                for (var i = pos; i + 1 < pending.Length; i++)
                {
                    if (pending[i] == '\r' && pending[i + 1] == '\n')
                    {
                        var line = Encoding.ASCII.GetString(pending, pos, i - pos);
                        pos = i + 2;
                        return line;
                    }
                }
                await EnsureBytesAsync(pending.Length - pos + 1).ConfigureAwait(false);
            }
        }

        while (true)
        {
            var sizeLine = await ReadLineAsync().ConfigureAwait(false);
            var semi = sizeLine.IndexOf(';');
            if (semi >= 0) sizeLine = sizeLine.Substring(0, semi);
            var chunkSize = Convert.ToInt32(sizeLine.Trim(), 16);
            if (chunkSize == 0) break;
            if (decoded.Length + chunkSize > MaxBodyBytes)
                throw new InvalidOperationException("Chunked payload too large.");

            await EnsureBytesAsync(chunkSize + 2).ConfigureAwait(false);
            decoded.Write(pending, pos, chunkSize);
            pos += chunkSize + 2; // skip trailing CRLF
        }

        return Utf8NoBom.GetString(decoded.GetBuffer(), 0, (int)decoded.Length);
    }

    private static int FindHeaderDelimiter(byte[] buffer, int length)
    {
        for (var i = 0; i + 3 < length; i++)
        {
            if (buffer[i] == '\r' && buffer[i + 1] == '\n' && buffer[i + 2] == '\r' && buffer[i + 3] == '\n')
                return i;
        }
        return -1;
    }

    private static async Task WriteJsonResponseAsync(NetworkStream stream, int statusCode, string reason, object payload, string? sessionId)
    {
        var json = McpServerConfigParser.SerializeJson(payload);
        var bodyBytes = Utf8NoBom.GetBytes(json);
        var sb = new StringBuilder();
        sb.Append("HTTP/1.1 ").Append(statusCode).Append(' ').Append(reason).Append("\r\n");
        sb.Append("Content-Type: application/json; charset=utf-8\r\n");
        sb.Append("Cache-Control: no-store\r\n");
        sb.Append("Connection: close\r\n");
        if (!string.IsNullOrWhiteSpace(sessionId))
            sb.Append("Mcp-Session-Id: ").Append(sessionId).Append("\r\n");
        sb.Append("Content-Length: ").Append(bodyBytes.Length).Append("\r\n\r\n");

        var headerBytes = Encoding.ASCII.GetBytes(sb.ToString());
        await stream.WriteAsync(headerBytes, 0, headerBytes.Length).ConfigureAwait(false);
        await stream.WriteAsync(bodyBytes, 0, bodyBytes.Length).ConfigureAwait(false);
        await stream.FlushAsync().ConfigureAwait(false);
    }

    private static async Task WriteEmptyResponseAsync(NetworkStream stream, int statusCode, string reason, string? extraHeaders)
    {
        var sb = new StringBuilder();
        sb.Append("HTTP/1.1 ").Append(statusCode).Append(' ').Append(reason).Append("\r\n");
        sb.Append("Cache-Control: no-store\r\n");
        sb.Append("Connection: close\r\n");
        if (!string.IsNullOrWhiteSpace(extraHeaders))
            sb.Append(extraHeaders);
        sb.Append("Content-Length: 0\r\n\r\n");

        var bytes = Encoding.ASCII.GetBytes(sb.ToString());
        await stream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);
        await stream.FlushAsync().ConfigureAwait(false);
    }

    private static Dictionary<string, object?> BuildRpcResult(object? id, object result) => new()
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id,
        ["result"] = result
    };

    private static Dictionary<string, object?> BuildRpcError(object? id, int code, string message) => new()
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id,
        ["error"] = new Dictionary<string, object?>
        {
            ["code"] = code,
            ["message"] = message
        }
    };

    private static string StripQuery(string path)
    {
        var q = path.IndexOf('?');
        return q >= 0 ? path.Substring(0, q) : path;
    }

    private static string? GetString(IDictionary<string, object?> map, string key)
    {
        if (!map.TryGetValue(key, out var val) || val == null) return null;
        return Convert.ToString(val);
    }

    private static bool GetBool(IDictionary<string, object?> map, string key, bool defaultValue)
    {
        if (!map.TryGetValue(key, out var val) || val == null) return defaultValue;
        if (val is bool b) return b;
        return bool.TryParse(Convert.ToString(val), out var parsed) ? parsed : defaultValue;
    }

    private static int? GetInt(IDictionary<string, object?> map, string key)
    {
        if (!map.TryGetValue(key, out var val) || val == null) return null;
        if (val is int i) return i;
        if (val is long l) return unchecked((int)l);
        return int.TryParse(Convert.ToString(val), out var parsed) ? parsed : null;
    }

    private sealed class HttpRequestData
    {
        public HttpRequestData(string method, string path, Dictionary<string, string> headers, string body)
        {
            Method = method;
            Path = path;
            Headers = headers;
            Body = body;
        }
        public string Method { get; }
        public string Path { get; }
        public Dictionary<string, string> Headers { get; }
        public string Body { get; }
    }
}
