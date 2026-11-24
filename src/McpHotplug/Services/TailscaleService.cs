using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using ServiceController = System.ServiceProcess.ServiceController;
using ServiceControllerStatus = System.ServiceProcess.ServiceControllerStatus;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace McpHotplug.Services;

internal sealed class TailscaleStatusEventArgs : EventArgs
{
    public TailscaleStatusEventArgs(string status, string? publicUrl, bool isHosting)
    {
        Status = status;
        PublicUrl = publicUrl;
        IsHosting = isHosting;
    }

    public string Status { get; }
    public string? PublicUrl { get; }
    public bool IsHosting { get; }
}

internal sealed class TailscaleLiveStatus
{
    public bool DaemonReachable { get; set; }
    public string BackendState { get; set; } = string.Empty;
    public bool SelfOnline { get; set; }
    public string DnsName { get; set; } = string.Empty;
    public string Ipv4 { get; set; } = string.Empty;
    public string AuthUrl { get; set; } = string.Empty;
    public List<string> Health { get; set; } = new();
    public bool HasFatalHealthError { get; set; }
    public string FatalHealthSummary { get; set; } = string.Empty;
    public string RawError { get; set; } = string.Empty;

    public bool IsTailnetOnline =>
        DaemonReachable &&
        string.Equals(BackendState, "Running", StringComparison.Ordinal) &&
        SelfOnline &&
        !HasFatalHealthError &&
        !string.IsNullOrWhiteSpace(Ipv4);
}

internal sealed class TailscaleService : IDisposable
{
    private const string ServiceName = "Tailscale";
    private const int LocalPort = 8004;
    private const string LocalPath = "/mcp";
    private const int ServiceStartupTimeoutMilliseconds = 30000;
    private const int FunnelStartupTimeoutMilliseconds = 120000;

    private static readonly Regex TailscaleIpv4Regex = new(
        @"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b",
        RegexOptions.Compiled);

    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly object _sync = new();
    private HostProcessState? _host;
    private string _status = I18n.Tr("Tailscale не подключён", "Tailscale is not connected");
    private string? _publicUrl;
    private bool _isVerifiedOnline;
    private bool _preferencesVerified;
    private bool _disposed;
    private bool _initialSetupComplete = HasCompletedInitialSetup();
    private bool _funnelCapabilityVerified;
    private DateTime _funnelCapabilityVerifiedUntil = DateTime.MinValue;
    private DateTime _nextFunnelCapabilityProbeUtc = DateTime.MinValue;
    private string? _pendingFunnelAuthorizationUrl;

    public event EventHandler<TailscaleStatusEventArgs>? StatusChanged;
    public event Action<string>? FunnelAuthorizationRequired;

    public string Status { get { lock (_sync) return _status; } }
    public string? PublicUrl { get { lock (_sync) return _isVerifiedOnline ? _publicUrl : null; } }
    public bool IsInitialSetupComplete { get { lock (_sync) return _initialSetupComplete; } }

    public bool IsPublished
    {
        get
        {
            lock (_sync)
            {
                if (!_isVerifiedOnline) return false;
                var host = _host;
                if (host == null || host.UrlReady.Task.Status != TaskStatus.RanToCompletion) return false;
                try { return !host.Process.HasExited; }
                catch (InvalidOperationException) { return false; }
            }
        }
    }

    public bool IsHosting
    {
        get
        {
            lock (_sync)
            {
                if (_host == null) return false;
                try { return !_host.Process.HasExited; }
                catch (InvalidOperationException) { return false; }
            }
        }
    }

    public void MarkOffline(string reason)
    {
        lock (_sync)
        {
            _isVerifiedOnline = false;
            _status = reason;
        }
    }

    /// <summary>
    /// Read-only registry check (no admin rights required): checks whether the Windows
    /// Tailscale service is already configured to route HTTPS through our local Smart-Relay.
    /// </summary>
    public static bool IsServiceProxyConfiguredForRelay()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tailscale");
            if (key == null) return false;
            if (key.GetValue("Environment") is not string[] lines) return false;

            var expected = "HTTPS_PROXY=" + TailscaleSmartRelay.RelayProxyUrl;
            return lines.Any(line => string.Equals(line?.Trim(), expected, StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Read-only registry check: verifies whether the Windows Tailscale service has
    /// GODEBUG=tlsmlkem=0 enabled so Go TLS 1.3 ClientHello stays within a single TCP segment.
    /// </summary>
    public static bool IsServiceMlkemDisabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tailscale");
            if (key == null) return false;
            if (key.GetValue("Environment") is not string[] lines) return false;

            foreach (var rawLine in lines)
            {
                var line = rawLine?.Trim();
                if (string.IsNullOrEmpty(line) || !line!.StartsWith("GODEBUG=", StringComparison.OrdinalIgnoreCase))
                    continue;
                var value = line.Substring("GODEBUG=".Length);
                if (value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .Any(tok => string.Equals(tok.Trim(), "tlsmlkem=0", StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    public static bool IsServiceFullyConfiguredForRelay() =>
        IsServiceProxyConfiguredForRelay() && IsServiceMlkemDisabled();

    /// <summary>
    /// One-time UAC helper that writes HTTPS_PROXY=http://127.0.0.1:18006 and GODEBUG=tlsmlkem=0
    /// to the Windows Tailscale service Environment (backing up previous values) and restarts tailscaled.
    /// </summary>
    public async Task EnsureServiceProxyConfiguredAsync(CancellationToken cancellationToken = default)
    {
        if (IsServiceFullyConfiguredForRelay())
            return;

        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (IsServiceFullyConfiguredForRelay())
                return;

            Publish(
                I18n.Tr(
                    "ПРАВА WINDOWS · Однократная настройка маршрутизации службы Tailscale…",
                    "WINDOWS PERMISSION · One-time Tailscale service routing setup…"),
                null,
                false);

            var result = await RunElevatedSetupHelperAsync(
                "ConfigureProxy",
                requestElevation: true,
                extraArguments: $"-ProxyUrl \"{TailscaleSmartRelay.RelayProxyUrl}\"",
                cancellationToken: cancellationToken).ConfigureAwait(false);

            if (result.ExitCode != 0 || GetOutputValue(result.Values, "ProxyConfigured") != "1")
            {
                var err = GetOutputValue(result.Values, "Error");
                if (string.IsNullOrWhiteSpace(err)) err = result.Output;
                throw new InvalidOperationException(
                    I18n.Tr("Не удалось настроить прокси для службы Tailscale: ", "Failed to configure proxy for the Tailscale service: ") + err);
            }

            ErrorLog.LogConnection(I18n.Tr(
                $"Служба Tailscale настроена на локальный Smart-Relay ({TailscaleSmartRelay.RelayProxyUrl}, tlsmlkem=0).",
                $"Tailscale service configured to use local Smart-Relay ({TailscaleSmartRelay.RelayProxyUrl}, tlsmlkem=0)."));
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async Task<TailscaleLiveStatus> GetLiveStatusAsync(CancellationToken cancellationToken = default)
    {
        var live = new TailscaleLiveStatus();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var executable = FindExecutable();
            if (string.IsNullOrWhiteSpace(executable))
            {
                live.RawError = "tailscale.exe not found";
                return live;
            }

            var statusResult = await RunCommandAsync(executable!, "status --json", 5000, cancellationToken).ConfigureAwait(false);
            if (statusResult.CombinedOutput.IndexOf("failed to connect to local tailscaled process", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                live.DaemonReachable = false;
                live.RawError = statusResult.CombinedOutput;
                return live;
            }

            if (string.IsNullOrWhiteSpace(statusResult.StandardOutput))
            {
                live.DaemonReachable = false;
                live.RawError = statusResult.CombinedOutput;
                return live;
            }

            live.DaemonReachable = true;
            ParseStatusJson(statusResult.StandardOutput, live);
            return live;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            live.DaemonReachable = false;
            live.RawError = ex.Message;
            return live;
        }
    }

    /// <summary>
    /// Local zero-external-traffic health check used while Online.
    /// Verifies: 1) foreground Funnel process alive, 2) BackendState=Running + Self.Online=true + clean Health,
    /// 3) funnel status --json confirms /mcp -> 127.0.0.1:8004 and AllowFunnel=true.
    /// </summary>
    public async Task<(bool Healthy, string Reason, TailscaleLiveStatus LiveStatus)> CheckRealOnlineHealthAsync(
        CancellationToken cancellationToken = default)
    {
        var live = await GetLiveStatusAsync(cancellationToken).ConfigureAwait(false);
        if (!IsHosting)
            return (false, "funnel_process_stopped", live);

        if (!live.DaemonReachable)
            return (false, "daemon_unreachable", live);

        if (!string.Equals(live.BackendState, "Running", StringComparison.Ordinal))
            return (false, "backend_" + live.BackendState, live);

        if (!live.SelfOnline || live.HasFatalHealthError)
            return (false, "self_offline", live);

        var executable = FindExecutable();
        if (string.IsNullOrWhiteSpace(executable))
            return (false, "cli_missing", live);

        var discoveredUrl = await TryDiscoverFunnelUrlAsync(executable!, LocalPath, cancellationToken, live.DnsName).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(discoveredUrl))
            return (false, "funnel_route_missing", live);

        return (true, "ok", live);
    }

    public async Task<bool> LaunchClientAsync(CancellationToken cancellationToken = default)
    {
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            await EnsureServiceRunningAsync(cancellationToken).ConfigureAwait(false);

            var cli = RequireExecutable();
            var directory = Path.GetDirectoryName(cli);
            var gui = string.IsNullOrWhiteSpace(directory) ? null : Path.Combine(directory, "tailscale-ipn.exe");
            if (string.IsNullOrWhiteSpace(gui) || !File.Exists(gui))
                throw new FileNotFoundException("Не найден графический клиент Tailscale (tailscale-ipn.exe).", gui);

            var sessionId = Process.GetCurrentProcess().SessionId;
            Process? existing = null;
            foreach (var candidate in Process.GetProcessesByName("tailscale-ipn"))
            {
                try
                {
                    if (existing == null && candidate.SessionId == sessionId)
                        existing = candidate;
                    else
                        candidate.Dispose();
                }
                catch { candidate.Dispose(); }
            }

            if (existing != null)
            {
                existing.Dispose();
                return true;
            }

            using var guiProcess = Process.Start(new ProcessStartInfo
            {
                FileName = gui,
                WorkingDirectory = directory!,
                UseShellExecute = true
            });

            if (guiProcess == null)
                throw new InvalidOperationException("Не удалось запустить графический клиент Tailscale.");

            return false;
        }
        finally
        {
            _operationGate.Release();
        }
    }

    /// <summary>
    /// Breaks tailscaled out of its internal 9s..60s exponential backoff without UAC
    /// by cycling WantRunning (down -> up). Preserves account login and machine keys.
    /// </summary>
    public async Task<bool> WakeDaemonReconnectAsync(CancellationToken cancellationToken = default)
    {
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var executable = FindExecutable();
            if (string.IsNullOrWhiteSpace(executable)) return false;

            var down = await RunCommandAsync(executable!, "down", 4000, cancellationToken).ConfigureAwait(false);
            if (ErrorLog.Enabled)
                ErrorLog.LogConnection($"[Tailscale][CLI] tailscale down exit={down.ExitCode}" + (string.IsNullOrWhiteSpace(down.CombinedOutput) ? string.Empty : $" out={down.CombinedOutput}"));
            if (down.ExitCode != 0)
                return false;

            try
            {
                var up = await RunCommandAsync(executable!, "up --accept-dns=false --unattended=true", 1500, CancellationToken.None).ConfigureAwait(false);
                if (ErrorLog.Enabled)
                    ErrorLog.LogConnection($"[Tailscale][CLI] tailscale up exit={up.ExitCode}" + (string.IsNullOrWhiteSpace(up.CombinedOutput) ? string.Empty : $" out={up.CombinedOutput}"));
            }
            catch (System.TimeoutException)
            {
                if (ErrorLog.Enabled)
                    ErrorLog.LogConnection("[Tailscale][CLI] tailscale up returned after 1500ms wait (daemon bringing up asynchronously).");
                // tailscaled receives WantRunning=true immediately; CLI waiting for online is expected.
            }
            return true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return false;
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async Task<string> BeginLoginAsync(CancellationToken cancellationToken = default)
    {
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            await EnsureServiceRunningAsync(cancellationToken).ConfigureAwait(false);

            var executable = RequireExecutable();
            var directory = Path.GetDirectoryName(executable) ?? AppPaths.InstallDirectory;
            var output = new StringBuilder();
            var error = new StringBuilder();
            var outputSync = new object();
            var authUrlSource = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = executable,
                    Arguments = "up --json --accept-dns=false --unattended=true",
                    WorkingDirectory = directory,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                },
                EnableRaisingEvents = true
            };

            process.OutputDataReceived += (_, args) =>
            {
                if (args.Data == null) return;
                lock (outputSync) output.AppendLine(args.Data);
                var url = ReadAuthUrl(args.Data);
                if (!string.IsNullOrWhiteSpace(url))
                    authUrlSource.TrySetResult(url ?? string.Empty);
            };
            process.ErrorDataReceived += (_, args) =>
            {
                if (args.Data == null) return;
                lock (outputSync) error.AppendLine(args.Data);
                var url = ReadAuthUrl(args.Data);
                if (!string.IsNullOrWhiteSpace(url))
                    authUrlSource.TrySetResult(url!);
            };

            if (!process.Start())
                throw new InvalidOperationException("Не удалось запустить команду tailscale up --json.");

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            var exitTask = Task.Run(() => process.WaitForExit());
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(20), cancellationToken);
            var completed = await Task.WhenAny(authUrlSource.Task, exitTask, timeoutTask).ConfigureAwait(false);

            if (completed == authUrlSource.Task)
            {
                var authUrl = await authUrlSource.Task.ConfigureAwait(false);
                try { if (!process.HasExited) process.Kill(); } catch { }
                await Task.WhenAny(exitTask, Task.Delay(2000)).ConfigureAwait(false);
                return authUrl;
            }

            if (completed == exitTask)
            {
                await exitTask.ConfigureAwait(false);
                if (authUrlSource.Task.IsCompleted)
                    return await authUrlSource.Task.ConfigureAwait(false);
                if (process.ExitCode == 0)
                    return string.Empty;
            }
            else
            {
                try { if (!process.HasExited) process.Kill(); } catch { }
                await Task.WhenAny(exitTask, Task.Delay(2000)).ConfigureAwait(false);
            }

            cancellationToken.ThrowIfCancellationRequested();

            string diagnostic;
            lock (outputSync)
                diagnostic = (output.ToString() + Environment.NewLine + error).Trim();

            if (completed == timeoutTask)
                throw new System.TimeoutException(
                    "Tailscale не вернул ссылку авторизации за 20 секунд." +
                    (string.IsNullOrWhiteSpace(diagnostic) ? string.Empty : Environment.NewLine + diagnostic));

            throw new InvalidOperationException(
                "Tailscale не смог создать ссылку авторизации. Код выхода: " + process.ExitCode +
                (string.IsNullOrWhiteSpace(diagnostic) ? string.Empty : Environment.NewLine + diagnostic));
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async Task<(bool IsConnected, string Details)> CheckConnectionAsync(CancellationToken cancellationToken = default)
    {
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            await EnsureServiceRunningAsync(cancellationToken).ConfigureAwait(false);
            var executable = RequireExecutable();

            var live = await GetLiveStatusAsync(cancellationToken).ConfigureAwait(false);
            var stateDetails = string.IsNullOrWhiteSpace(live.BackendState)
                ? live.RawError
                : $"Tailscale BackendState={live.BackendState}, Online={live.SelfOnline}";

            if (!live.DaemonReachable)
                return (false, "DEVICE_STATE_PENDING|" + stateDetails);

            if (string.Equals(live.BackendState, "NeedsLogin", StringComparison.Ordinal))
                return (false, "DEVICE_LOGIN_REQUIRED|" + live.AuthUrl + Environment.NewLine + stateDetails);

            if (string.Equals(live.BackendState, "NoState", StringComparison.Ordinal) ||
                string.Equals(live.BackendState, "Starting", StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(live.BackendState))
                return (false, "DEVICE_STATE_PENDING|" + stateDetails);

            if (string.Equals(live.BackendState, "NeedsMachineAuth", StringComparison.Ordinal))
                return (false, "DEVICE_APPROVAL_REQUIRED|" + I18n.Tr(
                    "Вход в аккаунт выполнен. Устройство ожидает одобрения администратора tailnet.",
                    "Account sign-in is complete. This device is waiting for tailnet administrator approval.") + Environment.NewLine + stateDetails);

            if (string.Equals(live.BackendState, "Stopped", StringComparison.Ordinal))
                return (false, "DEVICE_NOT_CONNECTED|" + I18n.Tr(
                    "Tailscale остановлен в системном трее. Откройте клиент и нажмите Connect.",
                    "Tailscale is stopped in the system tray. Open the client and click Connect."));

            // Critical fix: never trust a cached 100.x IP if Self.Online == false or Health reports coordination failure!
            if (!live.SelfOnline || live.HasFatalHealthError)
            {
                var healthSummary = live.Health.Count > 0 ? string.Join("; ", live.Health) : string.Empty;
                var healthMsg = !string.IsNullOrWhiteSpace(live.FatalHealthSummary)
                    ? live.FatalHealthSummary
                    : (!string.IsNullOrWhiteSpace(healthSummary)
                        ? $"Self.Online={live.SelfOnline} | Health: {healthSummary}"
                        : I18n.Tr("Демон Tailscale не в сети (нет связи с controlplane.tailscale.com).", "Tailscale daemon is offline (cannot reach controlplane.tailscale.com)."));
                return (false, "TAILNET_OFFLINE|" + healthMsg);
            }

            if (string.IsNullOrWhiteSpace(live.Ipv4))
                return (false, "DEVICE_NOT_CONNECTED|" + I18n.Tr(
                    "Tailscale запущен, но ещё не выдал адрес устройства.",
                    "Tailscale is running but has not assigned a device address yet."));

            if (!HasCompletedInitialSetup())
            {
                if (!string.IsNullOrWhiteSpace(_pendingFunnelAuthorizationUrl) &&
                    DateTime.UtcNow < _nextFunnelCapabilityProbeUtc)
                {
                    return (false, "FUNNEL_AUTHORIZATION_REQUIRED|" + _pendingFunnelAuthorizationUrl);
                }

                Publish(
                    I18n.Tr("Первичная настройка онлайн-доступа · проверяю разрешение Funnel", "Initial online setup · checking Funnel authorization"),
                    null,
                    false);

                var setup = await RunElevatedSetupHelperAsync(
                    "Activate",
                    requestElevation: false,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                var httpsSetupUrl = GetOutputValue(setup.Values, "HttpsSetupUrl");
                if (!string.IsNullOrWhiteSpace(httpsSetupUrl))
                {
                    if (!TryNormalizeHttpsSetupUrl(httpsSetupUrl, out var normalizedHttpsSetupUrl))
                        throw new InvalidOperationException("PowerShell helper вернул некорректную ссылку включения HTTPS Tailscale.");
                    return (false, "HTTPS_SETUP_REQUIRED|" + normalizedHttpsSetupUrl + Environment.NewLine + GetOutputValue(setup.Values, "Details"));
                }

                var authorizationUrl = GetOutputValue(setup.Values, "AuthorizationUrl");
                if (string.IsNullOrWhiteSpace(authorizationUrl))
                {
                    authorizationUrl = ReadFunnelApprovalUrl(string.Join(Environment.NewLine, new[]
                    {
                        setup.Output,
                        GetOutputValue(setup.Values, "Details"),
                        GetOutputValue(setup.Values, "Error"),
                        GetOutputValue(setup.Values, "Status")
                    })) ?? string.Empty;
                }

                if (!string.IsNullOrWhiteSpace(authorizationUrl))
                {
                    if (!TryNormalizeFunnelApprovalUrl(authorizationUrl, out var normalizedAuthorizationUrl))
                        throw new InvalidOperationException("PowerShell helper вернул некорректную ссылку подтверждения Funnel.");

                    _pendingFunnelAuthorizationUrl = normalizedAuthorizationUrl;
                    _nextFunnelCapabilityProbeUtc = DateTime.UtcNow.AddSeconds(6);
                    _funnelCapabilityVerified = false;
                    return (false, "FUNNEL_AUTHORIZATION_REQUIRED|" + normalizedAuthorizationUrl + Environment.NewLine +
                        I18n.Tr("Подтвердите включение Funnel на отдельной странице Tailscale.", "Approve Funnel on the separate Tailscale page."));
                }

                if (setup.ExitCode == 12)
                {
                    var offlineStatus = GetOutputValue(setup.Values, "Status");
                    return (false, "TAILNET_OFFLINE|" + (string.IsNullOrWhiteSpace(offlineStatus)
                        ? I18n.Tr("Tailscale не в сети (нет связи с controlplane).", "Tailscale is offline (cannot reach controlplane).")
                        : offlineStatus));
                }

                if (setup.ExitCode == 10)
                {
                    var connectStatus = GetOutputValue(setup.Values, "Status");
                    return (false, "DEVICE_NOT_CONNECTED|" + (string.IsNullOrWhiteSpace(connectStatus)
                        ? I18n.Tr("Подключите устройство в клиенте Tailscale и повторите проверку.", "Connect the device in the Tailscale client and retry.")
                        : connectStatus));
                }

                var setupConnected = GetOutputValue(setup.Values, "Connected") == "1";
                var funnelAuthorized = GetOutputValue(setup.Values, "FunnelAuthorized") == "1";
                var funnelVerified = GetOutputValue(setup.Values, "FunnelStatusVerified") == "1";
                var settingsApplied = GetOutputValue(setup.Values, "TailscaleSettingsApplied") == "1";
                var serviceRunning = GetOutputValue(setup.Values, "ServiceRunning") == "1";
                var unattended = GetOutputValue(setup.Values, "Unattended") == "1";
                var dnsDisabled = string.Equals(GetOutputValue(setup.Values, "Dns"), "disabled", StringComparison.OrdinalIgnoreCase);
                var setupAddress = GetOutputValue(setup.Values, "Address");
                var setupPublicUrl = GetOutputValue(setup.Values, "PublicUrl");
                var validAddress = TailscaleIpv4Regex.IsMatch(setupAddress);
                var validPublicUrl = Uri.TryCreate(setupPublicUrl, UriKind.Absolute, out var publicUri) &&
                    string.Equals(publicUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
                    publicUri.Host.EndsWith(".ts.net", StringComparison.OrdinalIgnoreCase);

                if (!(setupConnected && funnelAuthorized && funnelVerified && settingsApplied &&
                      serviceRunning && unattended && dnsDisabled && validAddress && validPublicUrl))
                {
                    var detailParts = new[]
                    {
                        GetOutputValue(setup.Values, "Status"),
                        GetOutputValue(setup.Values, "Error"),
                        GetOutputValue(setup.Values, "Details"),
                        setup.ExitCode == 0 ? string.Empty : "PowerShell exit code: " + setup.ExitCode,
                        setup.Output
                    }.Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.Ordinal).ToArray();
                    var details = detailParts.Length > 0
                        ? string.Join(Environment.NewLine, detailParts)
                        : I18n.Tr("Первичная настройка онлайн-доступа не завершена.", "Initial online setup did not complete.");
                    ErrorLog.WriteMessage("Tailscale.InitialSetup", details);
                    return (false, "SETUP_FAILED|" + details);
                }

                EnsureInitialSetupMarker();
                _funnelCapabilityVerified = true;
                _funnelCapabilityVerifiedUntil = DateTime.UtcNow.AddMinutes(5);
                _pendingFunnelAuthorizationUrl = null;
                _nextFunnelCapabilityProbeUtc = DateTime.MinValue;
            }
            else
            {
                await EnsureManagedPreferencesVerifiedOnceAsync(executable, cancellationToken).ConfigureAwait(false);
            }

            lock (_sync) _initialSetupComplete = HasCompletedInitialSetup();
            Publish(
                I18n.Tr("Онлайн-подключение Tailscale настроено · ", "Tailscale online connection is configured · ") + live.Ipv4,
                null,
                false);
            return (true, live.Ipv4);
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async Task StartHostingAsync(TailscaleRoute activeRoute, CancellationToken cancellationToken = default)
    {
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            if (IsHosting && IsPublished) return;
            if (IsHosting)
            {
                HostProcessState? oldHost;
                lock (_sync) oldHost = _host;
                await StopHostProcessAsync(oldHost).ConfigureAwait(false);
            }

            Publish(I18n.Tr("Проверка службы Tailscale…", "Checking Tailscale service…"), null, false);
            await EnsureServiceRunningAsync(cancellationToken).ConfigureAwait(false);
            var executable = RequireExecutable();
            await EnsureManagedPreferencesVerifiedOnceAsync(executable, cancellationToken).ConfigureAwait(false);

            var liveBefore = await GetLiveStatusAsync(cancellationToken).ConfigureAwait(false);
            if (!liveBefore.IsTailnetOnline)
            {
                var detail = !string.IsNullOrWhiteSpace(liveBefore.FatalHealthSummary)
                    ? liveBefore.FatalHealthSummary
                    : I18n.Tr("Tailscale не подключён к серверу координации.", "Tailscale is not connected to coordination server.");
                throw new InvalidOperationException(detail);
            }

            Publish(I18n.Tr("Публикация Funnel для Hotplug MCP Gateway :8004…", "Publishing Funnel for Hotplug MCP Gateway :8004…"), null, false);

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = executable,
                    Arguments = "funnel --yes --https=443 --set-path=" + LocalPath + " http://127.0.0.1:" + LocalPort + LocalPath,
                    WorkingDirectory = AppPaths.InstallDirectory,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                },
                EnableRaisingEvents = true
            };

            var job = new WindowsJobObject("Tailscale Funnel");
            var state = new HostProcessState(process, job);
            process.OutputDataReceived += (_, args) => HandleHostOutput(state, args.Data);
            process.ErrorDataReceived += (_, args) => HandleHostOutput(state, args.Data);
            process.Exited += (_, _) => HandleHostExit(state);

            try
            {
                lock (_sync)
                {
                    _host = state;
                    _isVerifiedOnline = false;
                }
                if (!process.Start()) throw new InvalidOperationException("Не удалось запустить Tailscale Funnel.");
                job.Assign(process);
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
            }
            catch
            {
                lock (_sync) { if (ReferenceEquals(_host, state)) _host = null; }
                try { if (process.Id > 0 && !process.HasExited) process.Kill(); } catch { }
                job.Dispose();
                process.Dispose();
                throw;
            }

            var funnelDeadline = DateTime.UtcNow.AddMilliseconds(FunnelStartupTimeoutMilliseconds);
            var approvalStatusPublished = false;
            await Task.WhenAny(state.UrlReady.Task, state.Exited.Task, Task.Delay(400, cancellationToken)).ConfigureAwait(false);

            while (!state.UrlReady.Task.IsCompleted &&
                   !state.Exited.Task.IsCompleted &&
                   DateTime.UtcNow < funnelDeadline)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (state.FunnelApprovalUrl.Task.IsCompleted && !approvalStatusPublished)
                {
                    approvalStatusPublished = true;
                    Publish(
                        I18n.Tr("ОЖИДАНИЕ · Требуется отдельно разрешить Tailscale Funnel в браузере.", "WAITING · Tailscale Funnel requires browser approval."),
                        null,
                        false);
                }

                var discoveredUrl = await TryDiscoverFunnelUrlAsync(executable, LocalPath, cancellationToken).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(discoveredUrl))
                    state.UrlReady.TrySetResult(discoveredUrl!);

                if (state.UrlReady.Task.IsCompleted || state.Exited.Task.IsCompleted)
                    break;

                await Task.WhenAny(state.UrlReady.Task, state.Exited.Task, Task.Delay(700, cancellationToken)).ConfigureAwait(false);
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (state.Exited.Task.IsCompleted && !state.UrlReady.Task.IsCompleted)
                throw new InvalidOperationException(
                    "Tailscale Funnel завершился до публикации URL. Код выхода: " + state.Exited.Task.Result + "." + Environment.NewLine + state.GetOutput());

            if (!state.UrlReady.Task.IsCompleted)
                throw new System.TimeoutException(
                    "Tailscale Funnel не опубликовал URL за " + FunnelStartupTimeoutMilliseconds / 1000 + " секунд." + Environment.NewLine + state.GetOutput());

            if (IsExited(process))
                throw new InvalidOperationException("Tailscale Funnel завершился сразу после публикации URL." + Environment.NewLine + state.GetOutput());

            var basePublicUrl = state.UrlReady.Task.Result.TrimEnd('/');
            var publicUrl = basePublicUrl + LocalPath;

            // Verify actual DNS propagation (never report green Online while *.ts.net returns NXDOMAIN).
            if (Uri.TryCreate(basePublicUrl, UriKind.Absolute, out var publicUri))
            {
                Publish(
                    I18n.Tr("ПРОВЕРКА DNS · Подтверждаю публикацию домена " + publicUri.Host + "…",
                            "DNS CHECK · Verifying publication of " + publicUri.Host + "…"),
                    null,
                    false);

                var dnsDeadline = DateTime.UtcNow.AddSeconds(18);
                var dnsState = PublicDnsState.Unknown;
                var consecutiveOffline = 0;
                while (DateTime.UtcNow < dnsDeadline)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var liveNow = await GetLiveStatusAsync(cancellationToken).ConfigureAwait(false);
                    if (!liveNow.IsTailnetOnline)
                    {
                        consecutiveOffline++;
                        if (consecutiveOffline >= 3)
                            throw new InvalidOperationException(I18n.Tr(
                                "Tailscale потерял связь с сервером координации во время публикации.",
                                "Tailscale lost connection to coordination server during publication."));

                        await Task.Delay(2000, cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    consecutiveOffline = 0;
                    dnsState = await TailscaleNetworkProbe
                        .CheckPublicDnsAsync(publicUri.Host, activeRoute ?? TailscaleRoute.Direct, cancellationToken)
                        .ConfigureAwait(false);
                    if (ErrorLog.Enabled)
                        ErrorLog.LogConnection($"[Tailscale][DNS] {publicUri.Host} via {(activeRoute ?? TailscaleRoute.Direct).DisplayName} -> {dnsState}");
                    if (dnsState == PublicDnsState.Resolved)
                        break;
                    await Task.Delay(2000, cancellationToken).ConfigureAwait(false);
                }

                if (consecutiveOffline > 0 && dnsState != PublicDnsState.Resolved)
                {
                    throw new InvalidOperationException(I18n.Tr(
                        "Tailscale потерял связь с сервером координации во время публикации.",
                        "Tailscale lost connection to coordination server during publication."));
                }

                if (dnsState == PublicDnsState.NxDomain)
                {
                    throw new InvalidOperationException(I18n.Tr(
                        $"Домен {publicUri.Host} ещё не опубликован в DNS (NXDOMAIN). Повторная проверка через 10 сек…",
                        $"Domain {publicUri.Host} is not published in DNS yet (NXDOMAIN). Retrying in 10s…"));
                }
            }

            lock (_sync) _isVerifiedOnline = true;
            ErrorLog.LogConnection(I18n.Tr(
                "Tailscale Funnel активен: " + publicUrl,
                "Tailscale Funnel is active: " + publicUrl));
            Publish(I18n.Tr("Tailscale Funnel активен", "Tailscale Funnel is active"), publicUrl, true);
        }
        catch (Exception exception)
        {
            lock (_sync) _isVerifiedOnline = false;
            HostProcessState? failedHost;
            lock (_sync) failedHost = _host;
            try { await StopHostProcessAsync(failedHost).ConfigureAwait(false); } catch { }
            Publish(
                I18n.Tr("Ошибка Tailscale Funnel: ", "Tailscale Funnel error: ") + exception.Message,
                null,
                false);
            throw;
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async Task StopHostingAsync()
    {
        await _operationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            HostProcessState? state;
            lock (_sync)
            {
                state = _host;
                _isVerifiedOnline = false;
            }

            var wasHosting = state != null;
            await StopHostProcessAsync(state).ConfigureAwait(false);
            if (wasHosting)
            {
                ErrorLog.LogConnection(I18n.Tr("Tailscale Funnel отключён.", "Tailscale Funnel disabled."));
            }
            Publish(I18n.Tr(
                "Tailscale Funnel отключён · служба Tailscale продолжает работать",
                "Tailscale Funnel is disabled · Tailscale service remains running"), null, false);
        }
        finally
        {
            _operationGate.Release();
        }
    }

    private async Task StopHostProcessAsync(HostProcessState? state)
    {
        if (state == null) return;

        state.ExpectedStop = true;
        try
        {
            var executable = FindExecutable();
            if (executable != null)
            {
                await RunCommandAsync(executable, "funnel --https=443 --set-path=" + LocalPath + " off", 3000).ConfigureAwait(false);
            }
        }
        catch (Exception exception) { ErrorLog.Write("Tailscale.FunnelOff", exception); }

        try
        {
            if (!IsExited(state.Process))
            {
                var exited = await Task.Run(() => state.Process.WaitForExit(1000)).ConfigureAwait(false);
                if (!exited && !IsExited(state.Process))
                {
                    state.Job.TryTerminateAll(out _);
                    state.Process.Kill();
                    await Task.Run(() => state.Process.WaitForExit(2000)).ConfigureAwait(false);
                }
            }
        }
        catch (InvalidOperationException) { }
        catch (System.ComponentModel.Win32Exception) { }

        HandleHostExit(state);
    }

    private async Task<bool> EnsureServiceRunningAsync(CancellationToken cancellationToken = default)
    {
        using var service = new ServiceController(ServiceName);
        try { service.Refresh(); }
        catch (InvalidOperationException)
        {
            throw new InvalidOperationException("Служба Tailscale не установлена. Повторите установку MCP Hotplug.");
        }
        catch (System.ComponentModel.Win32Exception exception) when (exception.NativeErrorCode == 1060)
        {
            throw new InvalidOperationException("Служба Tailscale не установлена. Повторите установку MCP Hotplug.", exception);
        }

        if (service.Status == ServiceControllerStatus.Running) return false;

        Publish(
            service.Status == ServiceControllerStatus.StartPending
                ? I18n.Tr("ОЖИДАНИЕ · Служба Tailscale уже запускается…", "WAITING · Tailscale service is already starting…")
                : I18n.Tr("ЗАПУСК · Запускаю службу Tailscale…", "STARTING · Starting the Tailscale service…"),
            null,
            false);

        async Task StartElevatedAsync()
        {
            Publish(
                I18n.Tr("ПРАВА WINDOWS · Запрашиваю разрешение на запуск службы Tailscale…", "WINDOWS PERMISSION · Requesting permission to start the Tailscale service…"),
                null,
                false);

            var elevatedStart = await RunElevatedSetupHelperAsync(
                "PrepareOnline",
                requestElevation: true,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            if (elevatedStart.ExitCode != 0 || GetOutputValue(elevatedStart.Values, "Prepared") != "1")
            {
                var details = GetOutputValue(elevatedStart.Values, "Error");
                if (string.IsNullOrWhiteSpace(details)) details = elevatedStart.Output;
                throw new InvalidOperationException("Не удалось запустить службу Tailscale с повышенными правами. " + details);
            }
            service.Refresh();
        }

        if (service.Status == ServiceControllerStatus.StopPending)
        {
            var stopDeadline = DateTime.UtcNow.AddSeconds(12);
            while (service.Status == ServiceControllerStatus.StopPending && DateTime.UtcNow < stopDeadline)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await Task.Delay(200, cancellationToken).ConfigureAwait(false);
                service.Refresh();
            }
            if (service.Status == ServiceControllerStatus.StopPending)
                throw new System.TimeoutException("Служба Tailscale не завершила остановку за 12 секунд.");
        }

        if (service.Status == ServiceControllerStatus.Paused)
        {
            try { service.Continue(); }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 5) { await StartElevatedAsync().ConfigureAwait(false); }
        }
        else if (service.Status != ServiceControllerStatus.StartPending &&
                 service.Status != ServiceControllerStatus.ContinuePending &&
                 service.Status != ServiceControllerStatus.Running)
        {
            try { service.Start(); }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 5) { await StartElevatedAsync().ConfigureAwait(false); }
            catch (System.ComponentModel.Win32Exception ex)
            {
                throw new InvalidOperationException("Hotplug не удалось запустить службу Tailscale. " + ex.Message, ex);
            }
        }

        var deadline = DateTime.UtcNow.AddMilliseconds(ServiceStartupTimeoutMilliseconds);
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            service.Refresh();
            if (service.Status == ServiceControllerStatus.Running) return true;
            if (service.Status == ServiceControllerStatus.Stopped)
                throw new InvalidOperationException("Служба Tailscale остановилась при запуске.");
            await Task.Delay(300, cancellationToken).ConfigureAwait(false);
        }

        throw new System.TimeoutException("Служба Tailscale не перешла в состояние Running за 30 секунд.");
    }

    private static void ParseStatusJson(string json, TailscaleLiveStatus target)
    {
        try
        {
            var serializer = new DataContractJsonSerializer(typeof(TailscaleStatusDto));
            using var ms = new MemoryStream(Encoding.UTF8.GetBytes(json));
            var dto = serializer.ReadObject(ms) as TailscaleStatusDto;
            if (dto != null)
            {
                target.BackendState = dto.BackendState ?? string.Empty;
                target.AuthUrl = dto.AuthURL ?? string.Empty;
                target.Health = (dto.Health ?? Array.Empty<string>())
                    .Where(h => !string.IsNullOrWhiteSpace(h))
                    .ToList();

                if (dto.Self != null)
                {
                    target.SelfOnline = dto.Self.Online;
                    target.DnsName = (dto.Self.DNSName ?? string.Empty).Trim().TrimEnd('.');
                    target.Ipv4 = (dto.Self.TailscaleIPs ?? Array.Empty<string>())
                        .FirstOrDefault(ip => !string.IsNullOrWhiteSpace(ip) && TailscaleIpv4Regex.IsMatch(ip)) ?? string.Empty;
                }

                EvaluateFatalHealth(target);
                return;
            }
        }
        catch { }

        // Fallback regex if JSON schema ever changes unexpectedly.
        var stateMatch = Regex.Match(json, "\"BackendState\"\\s*:\\s*\"(?<state>[^\"]+)\"", RegexOptions.IgnoreCase);
        if (stateMatch.Success) target.BackendState = stateMatch.Groups["state"].Value;
        target.AuthUrl = ReadAuthUrl(json) ?? string.Empty;
        target.SelfOnline = false;
    }

    private static void EvaluateFatalHealth(TailscaleLiveStatus status)
    {
        foreach (var entry in status.Health)
        {
            if (Regex.IsMatch(
                entry,
                @"coordination server|not connected|no derp|network.*down|tailscale is stopped|logged out|key.*expired|unable to connect|cannot connect",
                RegexOptions.IgnoreCase))
            {
                status.HasFatalHealthError = true;
                status.FatalHealthSummary = entry;
                return;
            }
        }
    }

    private string RequireExecutable()
    {
        var path = FindExecutable();
        if (path == null)
            throw new FileNotFoundException("Не найден tailscale.exe. Переустановите Tailscale из встроенного пакета MCP Hotplug.");
        return path;
    }

    private static string? FindExecutable()
    {
        var candidates = new[]
        {
            GetServiceExecutableSibling(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Tailscale", "tailscale.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Tailscale", "tailscale.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Tailscale", "tailscale.exe")
        };
        return candidates.FirstOrDefault(path => !string.IsNullOrWhiteSpace(path) && File.Exists(path));
    }

    private static string? GetServiceExecutableSibling()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tailscale");
            var imagePath = key?.GetValue("ImagePath") as string;
            if (string.IsNullOrWhiteSpace(imagePath)) return null;
            var match = Regex.Match(imagePath, "^\\s*\\\"(?<path>[^\\\"]+tailscaled\\.exe)\\\"|^\\s*(?<path>.+?tailscaled\\.exe)", RegexOptions.IgnoreCase);
            if (!match.Success) return null;
            var daemon = match.Groups["path"].Value.Trim();
            var directory = Path.GetDirectoryName(daemon);
            return string.IsNullOrWhiteSpace(directory) ? null : Path.Combine(directory, "tailscale.exe");
        }
        catch { return null; }
    }

    private static async Task<string?> TryDiscoverFunnelUrlAsync(
        string executable,
        string expectedPath,
        CancellationToken cancellationToken,
        string? knownDnsName = null)
    {
        try
        {
            var funnel = await RunCommandAsync(executable, "funnel status --json", 4500, cancellationToken).ConfigureAwait(false);
            if (funnel.ExitCode != 0 || string.IsNullOrWhiteSpace(funnel.StandardOutput) || !funnel.StandardOutput.Contains(expectedPath))
                return null;

            var host = (knownDnsName ?? string.Empty).Trim().TrimEnd('.');
            if (string.IsNullOrWhiteSpace(host))
            {
                var status = await RunCommandAsync(executable, "status --json", 4500, cancellationToken).ConfigureAwait(false);
                if (status.ExitCode == 0 && !string.IsNullOrWhiteSpace(status.StandardOutput))
                {
                    var hostMatch = Regex.Match(status.StandardOutput, "\"DNSName\"\\s*:\\s*\"(?<host>[a-z0-9.-]+\\.ts\\.net\\.?)\"", RegexOptions.IgnoreCase);
                    if (hostMatch.Success) host = hostMatch.Groups["host"].Value.TrimEnd('.');
                }
            }

            if (string.IsNullOrWhiteSpace(host))
            {
                var hostMatch = Regex.Match(funnel.StandardOutput, "\"(?<host>[a-z0-9.-]+\\.ts\\.net):443\"\\s*:", RegexOptions.IgnoreCase);
                if (hostMatch.Success) host = hostMatch.Groups["host"].Value.TrimEnd('.');
            }

            if (string.IsNullOrWhiteSpace(host)) return null;
            var allowPattern = "\"" + Regex.Escape(host) + ":443\"\\s*:\\s*true";
            var httpsPattern = "\"443\"\\s*:\\s*\\{\\s*\"HTTPS\"\\s*:\\s*true";
            if (!Regex.IsMatch(funnel.StandardOutput, allowPattern, RegexOptions.IgnoreCase) ||
                !Regex.IsMatch(funnel.StandardOutput, httpsPattern, RegexOptions.IgnoreCase))
                return null;

            return "https://" + host;
        }
        catch (OperationCanceledException) { throw; }
        catch { return null; }
    }

    private void HandleHostOutput(HostProcessState state, string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        state.AddOutput(line!);

        var approvalMatch = Regex.Match(line!, @"https://login\.tailscale\.com/f/funnel\?node=[^\s""'<>]+", RegexOptions.IgnoreCase);
        if (approvalMatch.Success)
        {
            var candidate = approvalMatch.Value.TrimEnd('.', ',', ')', ']', '"', '\'');
            if (TryNormalizeFunnelApprovalUrl(candidate, out var approvalUrl) &&
                state.FunnelApprovalUrl.TrySetResult(approvalUrl))
            {
                try { FunnelAuthorizationRequired?.Invoke(approvalUrl); } catch { }
            }
        }

        var match = Regex.Match(line!, @"https://[a-z0-9.-]+\.ts\.net", RegexOptions.IgnoreCase);
        if (match.Success)
            state.UrlReady.TrySetResult(match.Value);
    }

    private void HandleHostExit(HostProcessState state)
    {
        if (Interlocked.Exchange(ref state.CleanupStarted, 1) != 0) return;
        int exitCode = -1;
        try { exitCode = state.Process.ExitCode; } catch (InvalidOperationException) { }
        state.Exited.TrySetResult(exitCode);

        var isCurrent = false;
        lock (_sync)
        {
            if (ReferenceEquals(_host, state))
            {
                _host = null;
                _publicUrl = null;
                _isVerifiedOnline = false;
                isCurrent = true;
            }
        }

        state.Job.Dispose();
        state.Process.Dispose();

        if (isCurrent && !state.ExpectedStop)
        {
            var details = "Tailscale Funnel неожиданно завершился. Код выхода: " + exitCode + "." +
                (string.IsNullOrWhiteSpace(state.GetOutput()) ? string.Empty : Environment.NewLine + state.GetOutput());
            ErrorLog.WriteMessage("Tailscale.FunnelExited", details);
            Publish("Tailscale Funnel неожиданно завершился (код " + exitCode + ").", null, false);
            _ = RemoveManagedFunnelPathAsync();
        }
    }

    internal Task DisableManagedFunnelBestEffortAsync() => RemoveManagedFunnelPathAsync();

    private async Task RemoveManagedFunnelPathAsync()
    {
        try
        {
            var executable = FindExecutable();
            if (executable == null) return;
            var status = await RunCommandAsync(executable, "funnel status --json", 2000).ConfigureAwait(false);
            if (status.ExitCode != 0 || string.IsNullOrWhiteSpace(status.StandardOutput) || !status.StandardOutput.Contains(LocalPath))
                return;
            var result = await RunCommandAsync(executable, "funnel --https=443 --set-path=" + LocalPath + " off", 3000).ConfigureAwait(false);
            if (result.ExitCode != 0 && !string.IsNullOrWhiteSpace(result.CombinedOutput))
                ErrorLog.WriteMessage("Tailscale.FunnelExitCleanup", result.CombinedOutput);
        }
        catch (Exception exception) { ErrorLog.Write("Tailscale.FunnelExitCleanup", exception); }
    }

    private void Publish(string status, string? publicUrl, bool isHosting)
    {
        lock (_sync)
        {
            _status = status;
            _publicUrl = publicUrl;
        }
        StatusChanged?.Invoke(this, new TailscaleStatusEventArgs(status, publicUrl, isHosting));
    }

    private async Task EnsureManagedPreferencesVerifiedOnceAsync(string executable, CancellationToken cancellationToken)
    {
        if (_preferencesVerified) return;
        await VerifyManagedPreferencesAsync(executable, cancellationToken).ConfigureAwait(false);
        _preferencesVerified = true;
    }

    private static async Task VerifyManagedPreferencesAsync(string executable, CancellationToken cancellationToken = default)
    {
        var dnsTask = RunCommandAsync(executable, "get accept-dns", 5000, cancellationToken);
        var unattendedTask = RunCommandAsync(executable, "get unattended", 5000, cancellationToken);
        await Task.WhenAll(dnsTask, unattendedTask).ConfigureAwait(false);

        var dnsCheck = dnsTask.Result;
        EnsureSuccess("Проверка Tailscale accept-dns", dnsCheck);
        if (!string.Equals(dnsCheck.StandardOutput.Trim(), "false", StringComparison.OrdinalIgnoreCase))
        {
            var dnsSet = await RunCommandAsync(executable, "set --accept-dns=false", 8000, cancellationToken).ConfigureAwait(false);
            EnsureSuccess("Восстановление Tailscale accept-dns=false", dnsSet);
        }

        var unattendedCheck = unattendedTask.Result;
        EnsureSuccess("Проверка Tailscale unattended mode", unattendedCheck);
        if (!string.Equals(unattendedCheck.StandardOutput.Trim(), "true", StringComparison.OrdinalIgnoreCase))
        {
            var unattendedSet = await RunCommandAsync(executable, "set --unattended=true", 8000, cancellationToken).ConfigureAwait(false);
            EnsureSuccess("Восстановление Tailscale unattended=true", unattendedSet);
        }
    }

    private static bool HasCompletedInitialSetup()
    {
        var stateFile = Path.Combine(AppPaths.ConfigDirectory, "tailscale-state.txt");
        if (!File.Exists(stateFile)) return false;
        try
        {
            return File.ReadAllLines(stateFile).Any(line =>
                string.Equals(line.Trim(), "HotplugSetupComplete=1", StringComparison.Ordinal) ||
                string.Equals(line.Trim(), "BridgeSetupComplete=1", StringComparison.Ordinal));
        }
        catch { return false; }
    }

    private static void EnsureInitialSetupMarker()
    {
        if (HasCompletedInitialSetup()) return;
        Directory.CreateDirectory(AppPaths.ConfigDirectory);
        var stateFile = Path.Combine(AppPaths.ConfigDirectory, "tailscale-state.txt");
        var existingState = File.Exists(stateFile) ? File.ReadAllText(stateFile) : string.Empty;
        if (existingState.Length > 0 && !existingState.EndsWith("\n", StringComparison.Ordinal) && !existingState.EndsWith("\r", StringComparison.Ordinal))
            File.AppendAllText(stateFile, Environment.NewLine, Encoding.ASCII);
        File.AppendAllText(stateFile, "HotplugSetupComplete=1" + Environment.NewLine, Encoding.ASCII);
    }

    private async Task<string?> EnsureFunnelCapabilityAsync(CancellationToken cancellationToken)
    {
        if (_funnelCapabilityVerified && DateTime.UtcNow < _funnelCapabilityVerifiedUntil)
            return null;

        if (!string.IsNullOrWhiteSpace(_pendingFunnelAuthorizationUrl) && DateTime.UtcNow < _nextFunnelCapabilityProbeUtc)
            return _pendingFunnelAuthorizationUrl;

        var setup = await RunElevatedSetupHelperAsync("Activate", requestElevation: false, cancellationToken: cancellationToken).ConfigureAwait(false);

        if (setup.ExitCode == 12)
            return "TAILNET_OFFLINE|" + GetOutputValue(setup.Values, "Status");

        var httpsSetupUrl = GetOutputValue(setup.Values, "HttpsSetupUrl");
        if (!string.IsNullOrWhiteSpace(httpsSetupUrl))
        {
            if (!TryNormalizeHttpsSetupUrl(httpsSetupUrl, out var normalizedHttpsSetupUrl))
                throw new InvalidOperationException("PowerShell helper вернул некорректную ссылку включения HTTPS Tailscale.");
            _funnelCapabilityVerified = false;
            return "HTTPS_SETUP_REQUIRED|" + normalizedHttpsSetupUrl;
        }

        var rawAuthorizationUrl = GetOutputValue(setup.Values, "AuthorizationUrl");
        if (string.IsNullOrWhiteSpace(rawAuthorizationUrl))
        {
            rawAuthorizationUrl = ReadFunnelApprovalUrl(string.Join(Environment.NewLine, new[]
            {
                setup.Output, GetOutputValue(setup.Values, "Details"),
                GetOutputValue(setup.Values, "Error"), GetOutputValue(setup.Values, "Status")
            })) ?? string.Empty;
        }

        if (!string.IsNullOrWhiteSpace(rawAuthorizationUrl))
        {
            if (!TryNormalizeFunnelApprovalUrl(rawAuthorizationUrl, out var normalizedUrl))
                throw new InvalidOperationException("PowerShell helper вернул некорректную ссылку подтверждения Funnel.");
            _pendingFunnelAuthorizationUrl = normalizedUrl;
            _nextFunnelCapabilityProbeUtc = DateTime.UtcNow.AddSeconds(6);
            _funnelCapabilityVerified = false;
            return normalizedUrl;
        }

        var setupConnected = GetOutputValue(setup.Values, "Connected") == "1";
        var funnelAuthorized = GetOutputValue(setup.Values, "FunnelAuthorized") == "1";
        var funnelVerified = GetOutputValue(setup.Values, "FunnelStatusVerified") == "1";
        var settingsApplied = GetOutputValue(setup.Values, "TailscaleSettingsApplied") == "1";
        var serviceRunning = GetOutputValue(setup.Values, "ServiceRunning") == "1";
        var unattended = GetOutputValue(setup.Values, "Unattended") == "1";
        var dnsDisabled = string.Equals(GetOutputValue(setup.Values, "Dns"), "disabled", StringComparison.OrdinalIgnoreCase);
        var address = GetOutputValue(setup.Values, "Address");
        var publicUrl = GetOutputValue(setup.Values, "PublicUrl");
        var validAddress = TailscaleIpv4Regex.IsMatch(address);
        var validPublicUrl = Uri.TryCreate(publicUrl, UriKind.Absolute, out var publicUri) &&
            string.Equals(publicUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
            publicUri.Host.EndsWith(".ts.net", StringComparison.OrdinalIgnoreCase);

        if (setup.ExitCode != 0 || !setupConnected || !funnelAuthorized || !funnelVerified ||
            !settingsApplied || !serviceRunning || !unattended || !dnsDisabled || !validAddress || !validPublicUrl)
        {
            _funnelCapabilityVerified = false;
            _pendingFunnelAuthorizationUrl = null;
            _nextFunnelCapabilityProbeUtc = DateTime.UtcNow.AddSeconds(10);
            var details = string.Join(Environment.NewLine, new[]
            {
                GetOutputValue(setup.Values, "Status"), GetOutputValue(setup.Values, "Error"),
                GetOutputValue(setup.Values, "Details"), setup.Output,
                setup.ExitCode == 0 ? string.Empty : "PowerShell exit code: " + setup.ExitCode
            }.Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.Ordinal));
            throw new InvalidOperationException("Не удалось подтвердить разрешение Tailscale Funnel." +
                (string.IsNullOrWhiteSpace(details) ? string.Empty : Environment.NewLine + details));
        }

        EnsureInitialSetupMarker();
        _funnelCapabilityVerified = true;
        _funnelCapabilityVerifiedUntil = DateTime.UtcNow.AddMinutes(5);
        _pendingFunnelAuthorizationUrl = null;
        _nextFunnelCapabilityProbeUtc = DateTime.MinValue;
        return null;
    }

    private static bool TryNormalizeFunnelApprovalUrl(string value, out string normalizedUrl)
    {
        normalizedUrl = string.Empty;
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.Host, "login.tailscale.com", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.AbsolutePath, "/f/funnel", StringComparison.OrdinalIgnoreCase))
            return false;

        var hasNode = uri.Query.TrimStart('?').Split('&')
            .Any(p => p.StartsWith("node=", StringComparison.OrdinalIgnoreCase) && p.Length > 5 && !string.IsNullOrWhiteSpace(p.Substring(5)));
        if (!hasNode) return false;
        normalizedUrl = uri.AbsoluteUri;
        return true;
    }

    private static bool TryNormalizeHttpsSetupUrl(string value, out string normalizedUrl)
    {
        normalizedUrl = string.Empty;
        if (!Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.Host, "tailscale.com", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.AbsolutePath, "/s/https", StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(uri.UserInfo))
            return false;
        normalizedUrl = uri.AbsoluteUri;
        return true;
    }

    private static string? ReadFunnelApprovalUrl(string output)
    {
        if (string.IsNullOrWhiteSpace(output)) return null;
        var match = Regex.Match(output, @"https://login\.tailscale\.com/f/funnel\?node=[^\s""'<>]+", RegexOptions.IgnoreCase);
        if (!match.Success) return null;
        var candidate = match.Value.TrimEnd('.', ',', ')', ']');
        return TryNormalizeFunnelApprovalUrl(candidate, out var normalizedUrl) ? normalizedUrl : null;
    }

    private static string GetOutputValue(IDictionary<string, string> values, string key) =>
        values.TryGetValue(key, out var value) ? value : string.Empty;

    private static string? ReadAuthUrl(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        var match = Regex.Match(json, @"""AuthURL""\s*:\s*""(?<url>(?:\\.|[^""\\])*)""", RegexOptions.IgnoreCase);
        if (!match.Success) return null;
        var value = match.Groups["url"].Value.Replace("\\/", "/").Replace("\\u0026", "&");
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.Host, "login.tailscale.com", StringComparison.OrdinalIgnoreCase) ||
            !uri.AbsolutePath.StartsWith("/a/", StringComparison.OrdinalIgnoreCase))
            return null;
        return uri.AbsoluteUri;
    }

    private static async Task<SetupHelperResult> RunElevatedSetupHelperAsync(
        string mode,
        bool requestElevation = true,
        string? extraArguments = null,
        CancellationToken cancellationToken = default)
    {
        var scriptDirectory = Path.Combine(AppPaths.ConfigDirectory, "Temp");
        Directory.CreateDirectory(scriptDirectory);
        var helperId = Guid.NewGuid().ToString("N");
        var scriptPath = Path.Combine(scriptDirectory, "TailscaleSetup-" + helperId + ".ps1");
        var cancelFile = Path.Combine(scriptDirectory, "TailscaleSetup-" + helperId + ".cancel");
        var msiPath = Path.Combine(AppPaths.DependenciesDirectory, "tailscale-setup.msi");
        if (!File.Exists(msiPath) && Directory.Exists(AppPaths.DependenciesDirectory))
        {
            msiPath = Directory.GetFiles(AppPaths.DependenciesDirectory, "tailscale-setup-*.msi", SearchOption.TopDirectoryOnly)
                .OrderByDescending(path => File.GetLastWriteTimeUtc(path))
                .FirstOrDefault() ?? msiPath;
        }

        var stateFile = Path.Combine(AppPaths.ConfigDirectory, "tailscale-state.txt");
        var outputFile = Path.Combine(AppPaths.ConfigDirectory, "tailscale-helper-" + Guid.NewGuid().ToString("N") + ".txt");
        var powerShellPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");

        using (var embeddedScript = typeof(TailscaleService).Assembly.GetManifestResourceStream("TailscaleSetup.ps1"))
        {
            if (embeddedScript == null)
                throw new FileNotFoundException("В сборке MCPHotplug отсутствует EmbeddedResource TailscaleSetup.ps1.");
            using var reader = new StreamReader(embeddedScript, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            File.WriteAllText(scriptPath, reader.ReadToEnd().TrimStart('\uFEFF'), new UTF8Encoding(true));
        }

        var arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + scriptPath +
            "\" -Mode \"" + mode +
            "\" -MsiPath \"" + msiPath +
            "\" -StateFile \"" + stateFile +
            "\" -OutputFile \"" + outputFile +
            "\" -CancelFile \"" + cancelFile + "\"" +
            (string.IsNullOrWhiteSpace(extraArguments) ? string.Empty : " " + extraArguments);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var startInfo = new ProcessStartInfo
            {
                FileName = powerShellPath,
                Arguments = arguments,
                WorkingDirectory = AppPaths.InstallDirectory,
                UseShellExecute = requestElevation,
                Verb = requestElevation ? "runas" : string.Empty,
                CreateNoWindow = !requestElevation,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = !requestElevation,
                RedirectStandardError = !requestElevation
            };

            var startSource = new TaskCompletionSource<Process?>(TaskCreationOptions.RunContinuationsAsynchronously);
            var launchThread = new Thread(() =>
            {
                try { startSource.TrySetResult(Process.Start(startInfo)); }
                catch (Exception exception) { startSource.TrySetException(exception); }
            })
            {
                IsBackground = true,
                Name = "MCPHotplug Tailscale setup launcher"
            };
            launchThread.SetApartmentState(ApartmentState.STA);
            launchThread.Start();

            var startTask = startSource.Task;
            var launchCanceled = Task.Delay(Timeout.Infinite, cancellationToken);
            if (await Task.WhenAny(startTask, launchCanceled).ConfigureAwait(false) != startTask)
            {
                try { File.WriteAllText(cancelFile, "cancel"); } catch { }
                cancellationToken.ThrowIfCancellationRequested();
            }

            using var process = await startTask.ConfigureAwait(false);
            if (process == null)
                throw new InvalidOperationException("Не удалось запустить сценарий настройки Tailscale.");

            var stdoutTask = !requestElevation ? process.StandardOutput.ReadToEndAsync() : Task.FromResult(string.Empty);
            var stderrTask = !requestElevation ? process.StandardError.ReadToEndAsync() : Task.FromResult(string.Empty);

            var helperDeadline = DateTime.UtcNow.AddSeconds(75);
            try
            {
                while (!process.HasExited && DateTime.UtcNow < helperDeadline)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await Task.Delay(100, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                try { File.WriteAllText(cancelFile, "cancel"); } catch { }
                var cleanupDeadline = DateTime.UtcNow.AddSeconds(9);
                while (!process.HasExited && DateTime.UtcNow < cleanupDeadline)
                    await Task.Delay(100).ConfigureAwait(false);
                try { if (!process.HasExited) process.Kill(); process.WaitForExit(2000); } catch { }
                throw;
            }

            if (!process.HasExited)
            {
                try { File.WriteAllText(cancelFile, "timeout"); } catch { }
                try { if (!process.HasExited) process.Kill(); process.WaitForExit(3000); } catch { }
                throw new System.TimeoutException("Сценарий настройки Tailscale превысил 75 секунд.");
            }

            var consoleOutput = string.Empty;
            if (!requestElevation)
            {
                try
                {
                    await Task.WhenAll(stdoutTask, stderrTask).ConfigureAwait(false);
                    consoleOutput = (stdoutTask.Result + Environment.NewLine + stderrTask.Result).Trim();
                }
                catch { }
            }

            cancellationToken.ThrowIfCancellationRequested();
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var output = string.Empty;
            if (File.Exists(outputFile))
            {
                var lines = File.ReadAllLines(outputFile);
                output = string.Join(Environment.NewLine, lines);
                foreach (var line in lines)
                {
                    var sep = line.IndexOf('=');
                    if (sep <= 0) continue;
                    values[line.Substring(0, sep).Trim()] = line.Substring(sep + 1).Trim();
                }
            }

            if (string.IsNullOrWhiteSpace(output) && !string.IsNullOrWhiteSpace(consoleOutput))
                output = consoleOutput;

            return new SetupHelperResult(process.ExitCode, values, output);
        }
        finally
        {
            try { if (File.Exists(outputFile)) File.Delete(outputFile); } catch { }
            try { if (File.Exists(cancelFile)) File.Delete(cancelFile); } catch { }
            try { if (File.Exists(scriptPath)) File.Delete(scriptPath); } catch { }
        }
    }

    private static async Task<CommandResult> RunCommandAsync(
        string executable,
        string arguments,
        int timeoutMilliseconds,
        CancellationToken cancellationToken = default)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                Arguments = arguments,
                WorkingDirectory = AppPaths.InstallDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };

        cancellationToken.ThrowIfCancellationRequested();
        if (!process.Start()) throw new InvalidOperationException("Не удалось запустить Tailscale CLI: " + arguments);
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);

        try
        {
            while (!process.HasExited && DateTime.UtcNow < deadline)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(); process.WaitForExit(2000); } catch { }
            throw;
        }

        if (!process.HasExited)
        {
            try { process.Kill(); process.WaitForExit(2000); } catch { }
            throw new System.TimeoutException("Команда tailscale " + arguments + " превысила " + timeoutMilliseconds / 1000 + " секунд.");
        }
        await Task.WhenAll(stdoutTask, stderrTask).ConfigureAwait(false);
        return new CommandResult(process.ExitCode, stdoutTask.Result, stderrTask.Result);
    }

    private static void EnsureSuccess(string operation, CommandResult result)
    {
        if (result.ExitCode == 0) return;
        throw new InvalidOperationException(operation + " завершилось с кодом " + result.ExitCode + "." +
            (string.IsNullOrWhiteSpace(result.CombinedOutput) ? string.Empty : Environment.NewLine + result.CombinedOutput));
    }

    private static bool IsExited(Process process)
    {
        try { return process.HasExited; }
        catch (InvalidOperationException) { return true; }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(TailscaleService));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        HostProcessState? state;
        lock (_sync)
        {
            state = _host;
            _isVerifiedOnline = false;
        }
        if (state == null) return;
        state.ExpectedStop = true;
        try { state.Job.TryTerminateAll(out _); } catch { }
        try { if (!state.Process.HasExited) state.Process.Kill(); } catch { }
    }

    [DataContract]
    private sealed class TailscaleStatusDto
    {
        [DataMember(Name = "BackendState")] public string? BackendState { get; set; }
        [DataMember(Name = "AuthURL")] public string? AuthURL { get; set; }
        [DataMember(Name = "Health")] public string[]? Health { get; set; }
        [DataMember(Name = "Self")] public TailscaleSelfDto? Self { get; set; }
    }

    [DataContract]
    private sealed class TailscaleSelfDto
    {
        [DataMember(Name = "Online")] public bool Online { get; set; }
        [DataMember(Name = "DNSName")] public string? DNSName { get; set; }
        [DataMember(Name = "TailscaleIPs")] public string[]? TailscaleIPs { get; set; }
    }

    private sealed class HostProcessState
    {
        private readonly object _sync = new();
        private readonly Queue<string> _output = new();

        public HostProcessState(Process process, WindowsJobObject job) { Process = process; Job = job; }
        public Process Process { get; }
        public WindowsJobObject Job { get; }
        public TaskCompletionSource<string> UrlReady { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<string> FunnelApprovalUrl { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<int> Exited { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool ExpectedStop;
        public int CleanupStarted;

        public void AddOutput(string line)
        {
            lock (_sync) { _output.Enqueue(line); while (_output.Count > 60) _output.Dequeue(); }
        }

        public string GetOutput() { lock (_sync) return string.Join(Environment.NewLine, _output); }
    }

    private sealed class SetupHelperResult
    {
        public SetupHelperResult(int exitCode, Dictionary<string, string> values, string output)
        { ExitCode = exitCode; Values = values; Output = output; }
        public int ExitCode { get; }
        public Dictionary<string, string> Values { get; }
        public string Output { get; }
    }

    private sealed class CommandResult
    {
        public CommandResult(int exitCode, string standardOutput, string standardError)
        { ExitCode = exitCode; StandardOutput = standardOutput; StandardError = standardError; }
        public int ExitCode { get; }
        public string StandardOutput { get; }
        public string StandardError { get; }
        public string CombinedOutput => (StandardOutput + Environment.NewLine + StandardError).Trim();
    }
}