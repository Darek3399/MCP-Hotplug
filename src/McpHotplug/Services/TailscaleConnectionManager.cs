using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using McpHotplug.Models;

namespace McpHotplug.Services;

public enum TailscaleConnectionPhase
{
    Offline,
    Disconnected,
    Connecting,
    Reconnecting,
    Disconnecting,
    WaitingForLogin,
    WaitingForDeviceApproval,
    WaitingForHttpsSetup,
    WaitingForFunnelApproval,
    WaitingForGateway,
    Connected,
    Error
}

public sealed class TailscaleConnectionManager : IDisposable
{
    private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromMinutes(4);
    private static readonly TimeSpan SetupRetryInterval = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan RecoveryCheckInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan OnlineLocalHealthInterval = TimeSpan.FromSeconds(10);

    private readonly TailscaleService _service = new();
    private readonly TailscaleSmartRelay _relay = new();
    private readonly AppSettings _settings;
    private readonly Func<bool> _saveSettings;
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly object _sync = new();
    private readonly CancellationTokenSource _lifetimeCancellation = new();

    private Timer? _monitorTimer;
    private CancellationTokenSource? _activeConnection;
    private TailscaleConnectionPhase _phase;
    private string _statusText;
    private TailscaleRoute? _activeRoute;
    private DateTime _lastRouteVerifiedUtc = DateTime.MinValue;
    private DateTime _lastFailureClassificationUtc = DateTime.MinValue;
    private bool _proxyElevationDeclinedInSession;
    private bool _gatewayReady;
    private bool _started;
    private bool _busy;
    private volatile bool _shutdownStarted;
    private volatile bool _disposed;
    private int _monitorRunning;
    private string _lastOpenedFunnelApprovalUrl = string.Empty;
    private string _lastOpenedHttpsSetupUrl = string.Empty;

    public TailscaleConnectionManager(AppSettings settings, Func<bool> saveSettings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _saveSettings = saveSettings ?? throw new ArgumentNullException(nameof(saveSettings));
        _service.StatusChanged += Service_StatusChanged;
        _service.FunnelAuthorizationRequired += Service_FunnelAuthorizationRequired;
        _relay.RouteFailureDetected += Relay_RouteFailureDetected;

        NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
        SystemEvents.PowerModeChanged += OnPowerModeChanged;

        // If the Windows Tailscale service is already configured to use our local Smart-Relay,
        // start it immediately so even an inactive Funnel profile never breaks the service's network.
        // Only prewarm in background when Funnel auto-connect is disabled; otherwise ReconcileAsync
        // handles route selection under _operationGate without racing or aborting active tunnels.
        if (TailscaleService.IsServiceProxyConfiguredForRelay())
        {
            try
            {
                _relay.EnsureStarted();
                if (!_settings.TailscaleFunnelEnabled)
                    _ = PrewarmRelayRouteAsync(_lifetimeCancellation.Token);
            }
            catch (Exception ex) { ErrorLog.Write("TailscaleRelay.Startup", ex); }
        }

        if (_settings.TailscaleFunnelEnabled)
        {
            _phase = TailscaleConnectionPhase.Offline;
            _statusText = I18n.Tr(
                "ОФЛАЙН · Онлайн-доступ настроен, выполняется проверка подключения…",
                "OFFLINE · Online access is configured, verifying connection…");
        }
        else if (_service.IsInitialSetupComplete)
        {
            _phase = TailscaleConnectionPhase.Disconnected;
            _statusText = I18n.Tr(
                "ОТКЛЮЧЕНО · Онлайн-доступ ранее настраивался, но сейчас выключен.",
                "DISCONNECTED · Online access was configured before, but is currently turned off.");
        }
        else
        {
            _phase = TailscaleConnectionPhase.Offline;
            _statusText = I18n.Tr(
                "ОФЛАЙН · Онлайн-доступ ещё не настраивался. Локальная работа доступна.",
                "OFFLINE · Online access has not been configured. Local operation is available.");
        }
    }

    public event EventHandler? StatusChanged;

    public TailscaleConnectionPhase Phase { get { lock (_sync) return _phase; } }
    public string StatusText { get { lock (_sync) return _statusText; } }
    public string? PublicUrl => IsConnected ? _service.PublicUrl : null;
    public bool IsConnected => Phase == TailscaleConnectionPhase.Connected && _service.IsPublished;
    public bool IsEnabled => _settings.TailscaleFunnelEnabled;
    public bool IsInitialSetupComplete => _service.IsInitialSetupComplete;
    public bool IsBusy { get { lock (_sync) return _busy; } }

    public void Start(bool gatewayReady)
    {
        ThrowIfDisposed();
        if (_shutdownStarted) return;
        _gatewayReady = gatewayReady;
        _started = true;

        if (!_settings.TailscaleFunnelEnabled)
            return;

        if (!IsInitialSetupComplete)
        {
            SetStatus(TailscaleConnectionPhase.Offline, I18n.Tr(
                "ОФЛАЙН · Требуется первичная настройка онлайн-доступа.",
                "OFFLINE · Initial online access setup is required."));
            return;
        }

        if (!gatewayReady)
        {
            SetStatus(TailscaleConnectionPhase.WaitingForGateway, I18n.Tr(
                "ОЖИДАНИЕ · Локальный MCP-шлюз ещё не готов.",
                "WAITING · The local MCP gateway is not ready yet."));
            return;
        }

        ScheduleMonitor(TimeSpan.Zero);
    }

    public void NotifyGatewayAvailability(bool ready)
    {
        if (_disposed || _shutdownStarted || _gatewayReady == ready)
            return;

        _gatewayReady = ready;
        if (!_started || !_settings.TailscaleFunnelEnabled)
            return;

        if (!ready)
        {
            StopMonitor();
            _ = StopForGatewayUnavailableAsync();
            return;
        }

        if (IsInitialSetupComplete)
            ScheduleMonitor(TimeSpan.FromMilliseconds(500));
    }

    public async Task ToggleConnectionAsync()
    {
        ThrowIfDisposed();
        if (_shutdownStarted) return;

        bool busy;
        lock (_sync) busy = _busy;
        if (busy) return;

        if (IsConnected || (_settings.TailscaleFunnelEnabled && IsInitialSetupComplete))
            await DisconnectAsync();
        else
            await ConnectAsync();
    }

    public async Task ShutdownAsync()
    {
        if (_disposed || _shutdownStarted)
            return;

        _shutdownStarted = true;
        _lifetimeCancellation.Cancel();
        StopMonitor();
        UnsubscribeSystemEvents();

        CancellationTokenSource? activeConnection;
        lock (_sync) activeConnection = _activeConnection;
        activeConnection?.Cancel();

        var acquired = await _operationGate.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        if (!acquired)
        {
            try { await _service.DisableManagedFunnelBestEffortAsync().ConfigureAwait(false); } catch { }
            CleanupOwnedResources();
            return;
        }

        try
        {
            try { await _service.StopHostingAsync().ConfigureAwait(false); }
            finally { CleanupOwnedResources(); }
        }
        finally
        {
            _operationGate.Release();
        }
    }

    private async Task ConnectAsync()
    {
        if (!await _operationGate.WaitAsync(0))
            return;

        _proxyElevationDeclinedInSession = false;
        StopMonitor();

        var cancellation = new CancellationTokenSource();
        lock (_sync)
        {
            _activeConnection = cancellation;
            _busy = true;
        }
        RaiseStatusChanged();

        try
        {
            // Persist user's intent to stay connected if initial setup is already complete,
            // so transient network errors automatically trigger the 10s recovery timer.
            if (IsInitialSetupComplete && !_settings.TailscaleFunnelEnabled)
            {
                _settings.TailscaleFunnelEnabled = true;
                _saveSettings();
            }

            SetStatus(TailscaleConnectionPhase.Connecting, I18n.Tr(
                "ПОДКЛЮЧЕНИЕ · Проверяю состояние Tailscale…",
                "CONNECTING · Checking Tailscale status…"));
            var clientTask = _service.LaunchClientAsync(cancellation.Token);
            var liveTask = _service.GetLiveStatusAsync(cancellation.Token);
            await Task.WhenAll(clientTask, liveTask);

            var liveNow = liveTask.Result;
            var relayConfigured = TailscaleService.IsServiceProxyConfiguredForRelay();
            if (liveNow.IsTailnetOnline && (!relayConfigured || _relay.IsRunning))
            {
                // Daemon is already online on the active route: do NOT re-race or tear down its live tunnels!
                if (_activeRoute == null)
                {
                    _activeRoute = relayConfigured ? _relay.CurrentRoute : TailscaleRoute.Direct;
                    _lastRouteVerifiedUtc = DateTime.UtcNow;
                }
            }
            else
            {
                SetStatus(TailscaleConnectionPhase.Connecting, I18n.Tr(
                    "ПОДКЛЮЧЕНИЕ · Подбираю рабочий маршрут к Tailscale…",
                    "CONNECTING · Probing best route to Tailscale…"));
                await EnsureRouteAndRelayReadyAsync(allowElevation: true, forceClassify: true, cancellation.Token);
            }

            await RunConnectionFlowAsync(allowElevation: true, cancellation.Token, prelaunchedClientAlreadyRunning: clientTask.Result);
            cancellation.Token.ThrowIfCancellationRequested();

            var previousEnabled = _settings.TailscaleFunnelEnabled;
            _settings.TailscaleFunnelEnabled = true;
            if (!_saveSettings())
            {
                _settings.TailscaleFunnelEnabled = previousEnabled;
                throw new InvalidOperationException(I18n.Tr(
                    "Не удалось сохранить настройку онлайн-доступа. Проверьте права на папку Config.",
                    "Could not save the online access setting. Check write permissions for the Config folder."));
            }

            if (!_gatewayReady)
            {
                SetStatus(TailscaleConnectionPhase.WaitingForGateway, I18n.Tr(
                    "ПОДКЛЮЧЕНО · Ожидаю готовности локального MCP-шлюза для запуска Funnel.",
                    "CONNECTED · Waiting for the local MCP gateway before starting Funnel."));
                return;
            }

            SetStatus(TailscaleConnectionPhase.Connecting, I18n.Tr(
                "Запускаю публичный HTTPS-туннель…",
                "Starting the public HTTPS tunnel…"));
            cancellation.Token.ThrowIfCancellationRequested();
            await _service.StartHostingAsync(_activeRoute ?? TailscaleRoute.Direct, cancellation.Token);
            SetStatus(TailscaleConnectionPhase.Connected, BuildConnectedStatusText());
            ScheduleMonitor(OnlineLocalHealthInterval);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            try { await _service.StopHostingAsync(); } catch { }
            var phase = IsInitialSetupComplete ? TailscaleConnectionPhase.Disconnected : TailscaleConnectionPhase.Offline;
            SetStatus(phase, I18n.Tr("ПОДКЛЮЧЕНИЕ ОТМЕНЕНО.", "CONNECTION CANCELED."));
        }
        catch (Exception exception)
        {
            SetStatus(TailscaleConnectionPhase.Error,
                I18n.Tr("ОШИБКА ПОДКЛЮЧЕНИЯ · ", "CONNECTION ERROR · ") + exception.Message);
            ErrorLog.Write("TailscaleConnectionManager.Connect", exception);
            // If online access is already enabled by user, keep retrying every 10s automatically.
            if (_settings.TailscaleFunnelEnabled && IsInitialSetupComplete && _gatewayReady)
                ScheduleMonitor(RecoveryCheckInterval);
        }
        finally
        {
            lock (_sync)
            {
                if (ReferenceEquals(_activeConnection, cancellation))
                    _activeConnection = null;
                _busy = false;
            }
            cancellation.Dispose();
            _operationGate.Release();
            RaiseStatusChanged();
        }
    }

    /// <summary>
    /// Races Direct vs all system/env HTTP & SOCKS5 proxies against controlplane.tailscale.com.
    /// Automatically switches Smart-Relay route and configures the Windows Tailscale service once if needed.
    /// </summary>
    private async Task PrewarmRelayRouteAsync(CancellationToken cancellationToken)
    {
        try
        {
            var probe = await TailscaleNetworkProbe
                .RaceBestRouteAsync(preferredRoute: null, classifyOnFailure: false, cancellationToken)
                .ConfigureAwait(false);
            if (!probe.Success || probe.WinningRoute == null || _disposed || _shutdownStarted)
                return;

            // Never override _activeRoute or abort tunnels if ConnectAsync / ReconcileAsync is running.
            if (!await _operationGate.WaitAsync(0, cancellationToken).ConfigureAwait(false))
                return;
            try
            {
                if (_disposed || _shutdownStarted || _activeRoute != null)
                    return;

                var winner = probe.WinningRoute;
                _activeRoute = winner;
                _lastRouteVerifiedUtc = DateTime.UtcNow;
                if (_relay.IsRunning)
                    _relay.SetRoute(winner, abortExistingTunnels: true);
            }
            finally
            {
                _operationGate.Release();
            }
        }
        catch { }
    }

    private async Task<TailscaleRouteProbeResult> EnsureRouteAndRelayReadyAsync(
        bool allowElevation,
        bool forceClassify,
        CancellationToken cancellationToken,
        ISet<string>? excludedRouteKeys = null)
    {
        var hasExclusions = excludedRouteKeys != null && excludedRouteKeys.Count > 0;
        var cachedRoute = _activeRoute;
        if (!forceClassify && !hasExclusions && cachedRoute != null &&
            DateTime.UtcNow - _lastRouteVerifiedUtc < TimeSpan.FromSeconds(15))
        {
            var relayReady = TailscaleService.IsServiceProxyConfiguredForRelay();
            if (relayReady || cachedRoute.Kind == TailscaleRouteKind.Direct)
            {
                return new TailscaleRouteProbeResult
                {
                    Success = true,
                    WinningRoute = cachedRoute,
                    DiagnosticMessage = $"Using freshly verified route {cachedRoute}."
                };
            }
        }

        var preferred = (cachedRoute != null && (!hasExclusions || !excludedRouteKeys!.Contains(cachedRoute.Key)))
            ? cachedRoute
            : null;
        var shouldClassify = forceClassify || (DateTime.UtcNow - _lastFailureClassificationUtc >= TimeSpan.FromSeconds(25));
        var probe = await TailscaleNetworkProbe
            .RaceBestRouteAsync(preferred, shouldClassify, cancellationToken, excludedRouteKeys)
            .ConfigureAwait(false);

        if (!probe.Success || probe.WinningRoute == null)
        {
            if (shouldClassify) _lastFailureClassificationUtc = DateTime.UtcNow;
            throw new InvalidOperationException(probe.UserMessage);
        }

        var winner = probe.WinningRoute;
        var previousRoute = _activeRoute;
        _activeRoute = winner;
        _lastRouteVerifiedUtc = DateTime.UtcNow;

        var serviceUsesRelay = TailscaleService.IsServiceProxyConfiguredForRelay();
        if (serviceUsesRelay || winner.Kind != TailscaleRouteKind.Direct)
        {
            _relay.EnsureStarted();
            _relay.SetRoute(winner, abortExistingTunnels: !winner.Equals(previousRoute));
        }

        if (winner.Kind != TailscaleRouteKind.Direct && !serviceUsesRelay)
        {
            if (!allowElevation || _proxyElevationDeclinedInSession)
            {
                throw new InvalidOperationException(I18n.Tr(
                    $"Найден рабочий маршрут ({winner.DisplayName}), но для его подключения к службе Tailscale требуется однократное подтверждение прав администратора (нажмите «Подключить»).",
                    $"Working route found ({winner.DisplayName}), but one-time administrator confirmation is required to route the Tailscale service (click Connect)."));
            }

            try
            {
                await _service.EnsureServiceProxyConfiguredAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (IsElevationCanceled(ex))
            {
                _proxyElevationDeclinedInSession = true;
                throw new InvalidOperationException(I18n.Tr(
                    "Запрос прав администратора отменён. Без однократной настройки прокси служба Tailscale не сможет использовать VPN в режиме прокси.",
                    "Administrator prompt was canceled. Without one-time proxy setup, the Tailscale service cannot use system-proxy VPN."));
            }
        }

        return probe;
    }

    private async Task RunConnectionFlowAsync(
        bool allowElevation,
        CancellationToken cancellationToken,
        bool? prelaunchedClientAlreadyRunning = null)
    {
        lock (_sync)
        {
            _lastOpenedFunnelApprovalUrl = string.Empty;
            _lastOpenedHttpsSetupUrl = string.Empty;
        }
        var deadline = DateTime.UtcNow.Add(ConnectionTimeout);

        bool clientAlreadyRunning;
        if (prelaunchedClientAlreadyRunning.HasValue)
        {
            clientAlreadyRunning = prelaunchedClientAlreadyRunning.Value;
        }
        else
        {
            SetStatus(TailscaleConnectionPhase.Connecting, I18n.Tr(
                "ЗАПУСК · Проверяю клиент Tailscale в системном трее…",
                "STARTING · Checking the Tailscale system-tray client…"));
            clientAlreadyRunning = await _service.LaunchClientAsync(cancellationToken);
        }

        var loginUrlOpened = string.Empty;
        var loginRequestAttempted = false;
        var pendingSince = DateTime.MinValue;
        var offlineSince = DateTime.MinValue;
        var currentRouteOfflineSince = DateTime.MinValue;
        var wakeAttemptedForCurrentRoute = false;
        var failedTailnetRouteKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deviceApprovalPageOpened = false;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = await _service.CheckConnectionAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            if (result.IsConnected)
                return;

            var details = result.Details ?? string.Empty;

            if (details.StartsWith("TAILNET_OFFLINE|", StringComparison.Ordinal))
            {
                var now = DateTime.UtcNow;
                var firstOfflinePoll = offlineSince == DateTime.MinValue;
                if (firstOfflinePoll)
                {
                    offlineSince = now;
                    currentRouteOfflineSince = now;
                }
                var msg = details.Substring("TAILNET_OFFLINE|".Length).Trim();

                var routeLabel = (_activeRoute ?? TailscaleRoute.Direct).DisplayName;
                SetStatus(TailscaleConnectionPhase.Connecting, I18n.Tr(
                    $"ПОДКЛЮЧЕНИЕ · Вывожу Tailscale в сеть ({routeLabel})…",
                    $"CONNECTING · Bringing Tailscale online ({routeLabel})…"));

                // Give tailscaled enough time to complete down->up + PollNetMap on a clean route (12s)
                // before demoting the route and failing over to another candidate.
                var failoverWindow = _activeRoute != null &&
                    (_activeRoute.Kind == TailscaleRouteKind.HttpProxy ||
                     _activeRoute.Kind == TailscaleRouteKind.Socks5Proxy ||
                     _activeRoute.Kind == TailscaleRouteKind.Direct)
                    ? TimeSpan.FromSeconds(12)
                    : TimeSpan.FromSeconds(6);

                var shouldFailoverRoute = !firstOfflinePoll &&
                    _activeRoute != null &&
                    (now - currentRouteOfflineSince >= failoverWindow);

                if (shouldFailoverRoute)
                {
                    failedTailnetRouteKeys.Add(_activeRoute!.Key);
                    var probe = await EnsureRouteAndRelayReadyAsync(
                        allowElevation,
                        forceClassify: false,
                        cancellationToken,
                        failedTailnetRouteKeys).ConfigureAwait(false);
                    currentRouteOfflineSince = DateTime.UtcNow;
                    wakeAttemptedForCurrentRoute = false;
                    if (probe.Success && _relay.IsRunning)
                        _relay.AbortActiveTunnels();
                }
                else if (firstOfflinePoll)
                {
                    var probe = await EnsureRouteAndRelayReadyAsync(
                        allowElevation,
                        forceClassify: false,
                        cancellationToken,
                        failedTailnetRouteKeys).ConfigureAwait(false);
                    if (probe.Success && _relay.IsRunning)
                        _relay.AbortActiveTunnels();
                }

                // Give tailscaled 1.2s to reconnect naturally after AbortActiveTunnels before forcing down->up.
                if (!wakeAttemptedForCurrentRoute && (now - currentRouteOfflineSince >= TimeSpan.FromMilliseconds(1200)))
                {
                    wakeAttemptedForCurrentRoute = true;
                    await _service.WakeDaemonReconnectAsync(cancellationToken).ConfigureAwait(false);
                    await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
                    continue;
                }

                if (DateTime.UtcNow - offlineSince >= TimeSpan.FromSeconds(35))
                    throw new TimeoutException(msg);

                await Task.Delay(TimeSpan.FromMilliseconds(900), cancellationToken);
                continue;
            }
            else if (details.StartsWith("DEVICE_LOGIN_REQUIRED|", StringComparison.Ordinal))
            {
                pendingSince = DateTime.MinValue;
                offlineSince = DateTime.MinValue;
                var payload = details.Substring("DEVICE_LOGIN_REQUIRED|".Length);
                var separator = payload.IndexOfAny(new[] { '\r', '\n' });
                var authUrl = separator >= 0 ? payload.Substring(0, separator).Trim() : payload.Trim();

                if (string.IsNullOrWhiteSpace(authUrl) && string.IsNullOrWhiteSpace(loginUrlOpened) && !loginRequestAttempted)
                {
                    loginRequestAttempted = true;
                    SetStatus(TailscaleConnectionPhase.WaitingForLogin, I18n.Tr(
                        "АВТОРИЗАЦИЯ · Получаю ссылку для входа в аккаунт Tailscale…",
                        "AUTHENTICATION · Requesting a Tailscale sign-in link…"));
                    try { authUrl = await _service.BeginLoginAsync(cancellationToken); }
                    catch (TimeoutException) { authUrl = string.Empty; }
                }
                else if (!string.IsNullOrWhiteSpace(authUrl))
                {
                    loginRequestAttempted = true;
                }

                if (!string.IsNullOrWhiteSpace(authUrl) && !string.Equals(authUrl, loginUrlOpened, StringComparison.Ordinal))
                {
                    if (!Uri.TryCreate(authUrl, UriKind.Absolute, out var loginUri) ||
                        !string.Equals(loginUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(loginUri.Host, "login.tailscale.com", StringComparison.OrdinalIgnoreCase) ||
                        !loginUri.AbsolutePath.StartsWith("/a/", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("Tailscale вернул некорректную ссылку авторизации: " + authUrl);
                    }
                    Process.Start(new ProcessStartInfo { FileName = loginUri.AbsoluteUri, UseShellExecute = true });
                    loginUrlOpened = loginUri.AbsoluteUri;
                }

                SetStatus(TailscaleConnectionPhase.WaitingForLogin, string.IsNullOrWhiteSpace(loginUrlOpened)
                    ? I18n.Tr("ОЖИДАНИЕ ВХОДА · Войдите в аккаунт Tailscale из системного трея.", "WAITING FOR SIGN-IN · Sign in to Tailscale from the system tray.")
                    : I18n.Tr("АВТОРИЗАЦИЯ · Открыл ссылку входа Tailscale. После входа продолжу автоматически.", "AUTHENTICATION · Opened Tailscale sign-in link. Will continue automatically."));
            }
            else if (details.StartsWith("DEVICE_STATE_PENDING|", StringComparison.Ordinal))
            {
                if (pendingSince == DateTime.MinValue) pendingSince = DateTime.UtcNow;
                SetStatus(TailscaleConnectionPhase.Connecting, I18n.Tr(
                    "ОЖИДАНИЕ · Служба Tailscale инициализируется…",
                    "WAITING · Tailscale daemon is initializing…"));
                if (DateTime.UtcNow - pendingSince >= TimeSpan.FromSeconds(35))
                    throw new TimeoutException(details.Substring("DEVICE_STATE_PENDING|".Length).Trim());
            }
            else if (details.StartsWith("DEVICE_NOT_CONNECTED|", StringComparison.Ordinal))
            {
                if (pendingSince == DateTime.MinValue) pendingSince = DateTime.UtcNow;
                SetStatus(TailscaleConnectionPhase.WaitingForLogin, I18n.Tr(
                    clientAlreadyRunning
                        ? "ОЖИДАНИЕ ПОДКЛЮЧЕНИЯ · Откройте Tailscale в трее и нажмите Connect."
                        : "ОЖИДАНИЕ ПОДКЛЮЧЕНИЯ · Нажмите Connect в клиенте Tailscale.",
                    clientAlreadyRunning
                        ? "WAITING FOR CONNECTION · Open Tailscale in the tray and select Connect."
                        : "WAITING FOR CONNECTION · Select Connect in the Tailscale client."));
                if (DateTime.UtcNow - pendingSince >= TimeSpan.FromSeconds(45))
                    throw new TimeoutException(details.Substring("DEVICE_NOT_CONNECTED|".Length).Trim());
            }
            else if (details.StartsWith("DEVICE_APPROVAL_REQUIRED|", StringComparison.Ordinal))
            {
                pendingSince = DateTime.MinValue;
                if (!deviceApprovalPageOpened)
                {
                    Process.Start(new ProcessStartInfo { FileName = "https://console.tailscale.com/admin/machines", UseShellExecute = true });
                    deviceApprovalPageOpened = true;
                }
                SetStatus(TailscaleConnectionPhase.WaitingForDeviceApproval, I18n.Tr(
                    "ОДОБРЕНИЕ УСТРОЙСТВА · Подтвердите устройство в Tailscale Admin Console → Machines.",
                    "DEVICE APPROVAL · Approve this device in Tailscale Admin Console → Machines."));
            }
            else if (details.StartsWith("HTTPS_SETUP_REQUIRED|", StringComparison.Ordinal))
            {
                pendingSince = DateTime.MinValue;
                var payload = details.Substring("HTTPS_SETUP_REQUIRED|".Length);
                var sep = payload.IndexOfAny(new[] { '\r', '\n' });
                var url = sep >= 0 ? payload.Substring(0, sep).Trim() : payload.Trim();
                if (!OpenHttpsSetupPage(url))
                    throw new InvalidOperationException("Не удалось открыть ссылку включения HTTPS Tailscale.");
                SetStatus(TailscaleConnectionPhase.WaitingForHttpsSetup, I18n.Tr(
                    "НАСТРОЙКА HTTPS · Включите HTTPS-сертификаты в Tailscale. Продолжу автоматически.",
                    "HTTPS SETUP · Enable HTTPS certificates in Tailscale. Will continue automatically."));
            }
            else if (details.StartsWith("FUNNEL_AUTHORIZATION_REQUIRED|", StringComparison.Ordinal))
            {
                pendingSince = DateTime.MinValue;
                var payload = details.Substring("FUNNEL_AUTHORIZATION_REQUIRED|".Length);
                var sep = payload.IndexOfAny(new[] { '\r', '\n' });
                var url = sep >= 0 ? payload.Substring(0, sep).Trim() : payload.Trim();
                if (!OpenFunnelApprovalPage(url))
                    throw new InvalidOperationException("Не удалось открыть ссылку разрешения Tailscale Funnel.");
                SetStatus(TailscaleConnectionPhase.WaitingForFunnelApproval, I18n.Tr(
                    "РАЗРЕШЕНИЕ FUNNEL · Нажмите Enable на открывшейся странице Tailscale. Продолжу автоматически.",
                    "FUNNEL APPROVAL · Click Enable on the opened Tailscale page. Will continue automatically."));
            }
            else if (details.StartsWith("SETUP_FAILED|", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(details.Substring("SETUP_FAILED|".Length));
            }
            else
            {
                throw new InvalidOperationException(details);
            }

            await Task.Delay(SetupRetryInterval, cancellationToken);
        }

        throw new TimeoutException(I18n.Tr(
            "Время ожидания подключения истекло.",
            "Connection timed out."));
    }

    private async Task DisconnectAsync()
    {
        if (!await _operationGate.WaitAsync(0))
            return;

        lock (_sync) _busy = true;
        RaiseStatusChanged();
        try
        {
            SetStatus(TailscaleConnectionPhase.Disconnecting, I18n.Tr(
                "ОТКЛЮЧЕНИЕ · Останавливаю Funnel…",
                "DISCONNECTING · Stopping Funnel…"));

            var previousEnabled = _settings.TailscaleFunnelEnabled;
            _settings.TailscaleFunnelEnabled = false;
            if (!_saveSettings())
            {
                _settings.TailscaleFunnelEnabled = previousEnabled;
                throw new InvalidOperationException(I18n.Tr(
                    "Не удалось сохранить отключение онлайн-доступа.",
                    "Could not save the online access setting."));
            }

            // User explicitly disconnected -> completely stop the 10s recovery loop.
            StopMonitor();
            await _service.StopHostingAsync().ConfigureAwait(false);
            SetStatus(TailscaleConnectionPhase.Disconnected, I18n.Tr(
                "ОТКЛЮЧЕНО · Локальный MCP Hotplug продолжает работать.",
                "DISCONNECTED · Local MCP Hotplug remains available."));
            ErrorLog.LogConnection(I18n.Tr("Tailscale Funnel отключён пользователем.", "Tailscale Funnel disabled by user."));
        }
        catch (Exception exception)
        {
            SetStatus(TailscaleConnectionPhase.Error, I18n.Tr("ОШИБКА ОТКЛЮЧЕНИЯ · ", "DISCONNECT ERROR · ") + exception.Message);
            ErrorLog.Write("TailscaleConnectionManager.Disconnect", exception);
        }
        finally
        {
            lock (_sync) _busy = false;
            _operationGate.Release();
            RaiseStatusChanged();
        }
    }

    private void ScheduleMonitor(TimeSpan delay)
    {
        if (_disposed || _shutdownStarted || !_settings.TailscaleFunnelEnabled || !_gatewayReady || !IsInitialSetupComplete)
            return;

        lock (_sync)
        {
            if (_monitorTimer == null)
                _monitorTimer = new Timer(MonitorTimer_Tick, null, delay, Timeout.InfiniteTimeSpan);
            else
                _monitorTimer.Change(delay, Timeout.InfiniteTimeSpan);
        }
    }

    private void StopMonitor()
    {
        lock (_sync)
        {
            _monitorTimer?.Dispose();
            _monitorTimer = null;
        }
    }

    private void MonitorTimer_Tick(object? state)
    {
        if (_shutdownStarted || _disposed) return;
        _ = ReconcileAsync(_lifetimeCancellation.Token);
    }

    /// <summary>
    /// Single-flight background loop:
    /// - While Online: performs ONLY a lightweight local daemon/funnel check (no external probes).
    /// - When disconnected unexpectedly (user did NOT click Disconnect): immediately reflects offline/reconnecting
    ///   state in UI and runs full route-race + recovery every 10 seconds until back online.
    /// </summary>
    private async Task ReconcileAsync(CancellationToken cancellationToken)
    {
        if (_disposed || _shutdownStarted || cancellationToken.IsCancellationRequested ||
            !_settings.TailscaleFunnelEnabled || !_gatewayReady || !IsInitialSetupComplete ||
            Interlocked.Exchange(ref _monitorRunning, 1) != 0)
            return;

        if (!await _operationGate.WaitAsync(0).ConfigureAwait(false))
        {
            Interlocked.Exchange(ref _monitorRunning, 0);
            if (!_shutdownStarted && !_disposed && _settings.TailscaleFunnelEnabled && _gatewayReady && IsInitialSetupComplete)
                ScheduleMonitor(TimeSpan.FromSeconds(2));
            return;
        }

        var nextDelay = RecoveryCheckInterval;
        try
        {
            if (cancellationToken.IsCancellationRequested || _disposed || _shutdownStarted ||
                !_settings.TailscaleFunnelEnabled || !_gatewayReady)
                return;

            // 1. Lightweight local check first (0 external traffic while genuinely Online).
            if (_service.IsPublished)
            {
                var health = await _service.CheckRealOnlineHealthAsync(cancellationToken).ConfigureAwait(false);
                if (health.Healthy)
                {
                    SetStatus(TailscaleConnectionPhase.Connected, BuildConnectedStatusText());
                    nextDelay = OnlineLocalHealthInterval;
                    return;
                }

                // 2-strike confirmation: ignore brief 1s stream recycles (e.g. VPN proxy idle reconnect)
                // unless the foreground Funnel process itself exited.
                if (!string.Equals(health.Reason, "funnel_process_stopped", StringComparison.Ordinal))
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(2500), cancellationToken).ConfigureAwait(false);
                    health = await _service.CheckRealOnlineHealthAsync(cancellationToken).ConfigureAwait(false);
                    if (health.Healthy)
                    {
                        SetStatus(TailscaleConnectionPhase.Connected, BuildConnectedStatusText());
                        nextDelay = OnlineLocalHealthInterval;
                        return;
                    }
                }

                // Confirmed real disconnect! Drop the "Connected" state in UI and start 10s recovery cycle.
                _service.MarkOffline(health.Reason);
                ErrorLog.LogConnection($"[Tailscale] Real disconnect confirmed ({health.Reason}). Starting 10s recovery cycle.");
                SetStatus(TailscaleConnectionPhase.Reconnecting, I18n.Tr(
                    "ПЕРЕПОДКЛЮЧЕНИЕ · Соединение потеряно, проверяю сеть и маршруты…",
                    "RECONNECTING · Connection lost, probing network routes…"));
                if (_service.IsHosting)
                    await _service.StopHostingAsync().ConfigureAwait(false);
            }

            // 2. Full recovery attempt (route race Direct vs Proxy -> Smart-Relay -> Daemon online -> Funnel + DNS).
            SetStatus(TailscaleConnectionPhase.Reconnecting, I18n.Tr(
                "ПЕРЕПОДКЛЮЧЕНИЕ · Проверяю доступность Tailscale (Direct / Proxy)…",
                "RECONNECTING · Probing Tailscale reachability (Direct / Proxy)…"));

            var routeTask = EnsureRouteAndRelayReadyAsync(
                allowElevation: !_proxyElevationDeclinedInSession,
                forceClassify: false,
                cancellationToken);
            var clientTask = _service.LaunchClientAsync(cancellationToken);
            await Task.WhenAll(routeTask, clientTask).ConfigureAwait(false);

            // Wait for tailscaled to become online over the winning route (bounded so 10s cadence stays responsive).
            using var recoveryCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            recoveryCts.CancelAfter(TimeSpan.FromSeconds(40));
            await RunConnectionFlowAsync(
                allowElevation: !_proxyElevationDeclinedInSession,
                recoveryCts.Token,
                prelaunchedClientAlreadyRunning: clientTask.Result).ConfigureAwait(false);

            SetStatus(TailscaleConnectionPhase.Reconnecting, I18n.Tr(
                "ПЕРЕПОДКЛЮЧЕНИЕ · Поднимаю публичный HTTPS-туннель…",
                "RECONNECTING · Starting public HTTPS tunnel…"));
            var route = _activeRoute ?? TailscaleRoute.Direct;
            await _service.StartHostingAsync(route, recoveryCts.Token).ConfigureAwait(false);

            SetStatus(TailscaleConnectionPhase.Connected, BuildConnectedStatusText());
            ErrorLog.LogConnection(I18n.Tr(
                $"Tailscale Funnel восстановлен ({route.DisplayName}): {_service.PublicUrl}",
                $"Tailscale Funnel recovered ({route.DisplayName}): {_service.PublicUrl}"));
            nextDelay = OnlineLocalHealthInterval;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }
        catch (OperationCanceledException)
        {
            var timeoutMsg = I18n.Tr(
                "Превышено время ожидания ответа от Tailscale. Повтор через 10 сек…",
                "Timed out waiting for Tailscale to come online. Retrying in 10s…");
            _service.MarkOffline(timeoutMsg);
            if (!_shutdownStarted && !_disposed && _settings.TailscaleFunnelEnabled)
            {
                SetStatus(TailscaleConnectionPhase.Offline,
                    I18n.Tr("ОФЛАЙН · ", "OFFLINE · ") + timeoutMsg);
            }
            nextDelay = RecoveryCheckInterval;
        }
        catch (Exception exception)
        {
            _service.MarkOffline(exception.Message);
            if (!_shutdownStarted && !_disposed && _settings.TailscaleFunnelEnabled)
            {
                SetStatus(TailscaleConnectionPhase.Offline,
                    I18n.Tr("ОФЛАЙН · ", "OFFLINE · ") + exception.Message);
            }
            nextDelay = RecoveryCheckInterval;
        }
        finally
        {
            _operationGate.Release();
            Interlocked.Exchange(ref _monitorRunning, 0);
            if (!_shutdownStarted && !_disposed && _settings.TailscaleFunnelEnabled && _gatewayReady && IsInitialSetupComplete)
                ScheduleMonitor(nextDelay);
            RaiseStatusChanged();
        }
    }

    private string BuildConnectedStatusText()
    {
        var route = _activeRoute ?? TailscaleRoute.Direct;
        var routeSuffix = route.Kind switch
        {
            TailscaleRouteKind.Direct => I18n.Tr("напрямую", "direct"),
            TailscaleRouteKind.DirectTlsSplit => I18n.Tr("напрямую · обход DPI (TLS)", "direct · DPI-safe (TLS)"),
            TailscaleRouteKind.DirectTcpSplit => I18n.Tr("напрямую · обход DPI (TCP)", "direct · DPI-safe (TCP)"),
            _ => route.DisplayName
        };
        return I18n.Tr(
            $"ПОДКЛЮЧЕНО · Публичный HTTPS-туннель активен ({routeSuffix}).",
            $"CONNECTED · Public HTTPS tunnel is active ({routeSuffix}).");
    }

    private void OnNetworkAddressChanged(object? sender, EventArgs e)
    {
        if (_disposed || _shutdownStarted || !_settings.TailscaleFunnelEnabled || !_gatewayReady)
            return;
        ScheduleMonitor(Phase == TailscaleConnectionPhase.Connected
            ? TimeSpan.FromSeconds(3)
            : TimeSpan.FromMilliseconds(1200));
    }

    private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode != PowerModes.Resume) return;
        if (_disposed || _shutdownStarted || !_settings.TailscaleFunnelEnabled || !_gatewayReady)
            return;
        ScheduleMonitor(TimeSpan.FromSeconds(2));
    }

    private void Relay_RouteFailureDetected(object? sender, string reason)
    {
        if (_disposed || _shutdownStarted) return;
        // Only accelerate recovery when dropping out of Connected;
        // while already offline/reconnecting, let the strict 10-second timer govern retries.
        if (Phase != TailscaleConnectionPhase.Connected) return;
        if (_settings.TailscaleFunnelEnabled && _gatewayReady && IsInitialSetupComplete)
            ScheduleMonitor(TimeSpan.FromMilliseconds(800));
    }

    private async Task StopForGatewayUnavailableAsync()
    {
        if (_disposed || _shutdownStarted || !_settings.TailscaleFunnelEnabled) return;
        if (!await _operationGate.WaitAsync(0).ConfigureAwait(false)) return;

        RaiseStatusChanged();
        try
        {
            if (_service.IsHosting)
                await _service.StopHostingAsync().ConfigureAwait(false);

            SetStatus(TailscaleConnectionPhase.WaitingForGateway, I18n.Tr(
                "ОЖИДАНИЕ · Локальный MCP-шлюз остановлен. Funnel будет запущен после его восстановления.",
                "WAITING · The local MCP gateway stopped. Funnel will start when it becomes available again."));
        }
        catch (Exception exception)
        {
            SetStatus(TailscaleConnectionPhase.Error, I18n.Tr("ОШИБКА ОСТАНОВКИ ТУННЕЛЯ · ", "TUNNEL STOP ERROR · ") + exception.Message);
            ErrorLog.Write("TailscaleConnectionManager.GatewayUnavailable", exception);
        }
        finally
        {
            _operationGate.Release();
            RaiseStatusChanged();
        }
    }

    private static bool IsElevationCanceled(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
        {
            if (current is Win32Exception win32Exception && win32Exception.NativeErrorCode == 1223)
                return true;
            if (current.HResult == unchecked((int)0x800704C7))
                return true;
        }
        return false;
    }

    private void Service_FunnelAuthorizationRequired(string authorizationUrl)
    {
        if (_disposed || _shutdownStarted) return;
        if (OpenFunnelApprovalPage(authorizationUrl))
        {
            SetStatus(TailscaleConnectionPhase.WaitingForFunnelApproval, I18n.Tr(
                "РАЗРЕШЕНИЕ FUNNEL · Открыл отдельную страницу подтверждения Funnel. Нажмите Enable.",
                "FUNNEL APPROVAL · Opened the Funnel approval page. Select Enable."));
        }
    }

    private bool OpenHttpsSetupPage(string value)
    {
        if (!Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.Host, "tailscale.com", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.AbsolutePath, "/s/https", StringComparison.OrdinalIgnoreCase))
            return false;

        var setupUrl = uri.AbsoluteUri;
        lock (_sync)
        {
            if (string.Equals(_lastOpenedHttpsSetupUrl, setupUrl, StringComparison.Ordinal)) return true;
            _lastOpenedHttpsSetupUrl = setupUrl;
        }
        try { Process.Start(new ProcessStartInfo { FileName = setupUrl, UseShellExecute = true }); return true; }
        catch (Exception ex) { lock (_sync) _lastOpenedHttpsSetupUrl = string.Empty; ErrorLog.Write("TailscaleConnectionManager.OpenHttpsSetupPage", ex); return false; }
    }

    private bool OpenFunnelApprovalPage(string value)
    {
        if (!Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.Host, "login.tailscale.com", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.AbsolutePath, "/f/funnel", StringComparison.OrdinalIgnoreCase))
            return false;

        var authorizationUrl = uri.AbsoluteUri;
        lock (_sync)
        {
            if (string.Equals(_lastOpenedFunnelApprovalUrl, authorizationUrl, StringComparison.Ordinal)) return true;
            _lastOpenedFunnelApprovalUrl = authorizationUrl;
        }
        try { Process.Start(new ProcessStartInfo { FileName = authorizationUrl, UseShellExecute = true }); return true; }
        catch (Exception ex) { lock (_sync) _lastOpenedFunnelApprovalUrl = string.Empty; ErrorLog.Write("TailscaleConnectionManager.OpenFunnelApprovalPage", ex); return false; }
    }

    private void Service_StatusChanged(object? sender, TailscaleStatusEventArgs e)
    {
        if (_disposed) return;

        if (_service.IsPublished)
        {
            SetStatus(TailscaleConnectionPhase.Connected, BuildConnectedStatusText());
        }
        else if (_busy && _phase == TailscaleConnectionPhase.Connecting)
        {
            SetStatus(TailscaleConnectionPhase.Connecting, e.Status);
        }
        else if (_settings.TailscaleFunnelEnabled && _phase == TailscaleConnectionPhase.Connected)
        {
            SetStatus(TailscaleConnectionPhase.Reconnecting, I18n.Tr(
                "ПЕРЕПОДКЛЮЧЕНИЕ · Туннель прервался, выполняется восстановление…",
                "RECONNECTING · Tunnel dropped, recovering…"));
            ScheduleMonitor(TimeSpan.FromSeconds(1));
        }
        else
        {
            RaiseStatusChanged();
        }
    }

    private void SetStatus(TailscaleConnectionPhase phase, string message)
    {
        if (_disposed || _shutdownStarted) return;

        var changed = false;
        var phaseChanged = false;
        TailscaleConnectionPhase previousPhase;
        lock (_sync)
        {
            if (_disposed || _shutdownStarted) return;
            previousPhase = _phase;
            if (_phase != phase || !string.Equals(_statusText, message, StringComparison.Ordinal))
            {
                phaseChanged = _phase != phase;
                _phase = phase;
                _statusText = message;
                changed = true;
            }
        }

        if (phaseChanged)
            ErrorLog.LogConnection("[Tailscale] " + previousPhase + " -> " + phase + " · " + message);
        if (changed)
            RaiseStatusChanged();
    }

    private void RaiseStatusChanged()
    {
        if (_disposed || _shutdownStarted) return;
        StatusChanged?.Invoke(this, EventArgs.Empty);
    }

    private void UnsubscribeSystemEvents()
    {
        try { NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged; } catch { }
        try { SystemEvents.PowerModeChanged -= OnPowerModeChanged; } catch { }
    }

    private void CleanupOwnedResources()
    {
        _service.StatusChanged -= Service_StatusChanged;
        _service.FunnelAuthorizationRequired -= Service_FunnelAuthorizationRequired;
        _relay.RouteFailureDetected -= Relay_RouteFailureDetected;
        _service.Dispose();
        _relay.Dispose();
        _disposed = true;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(TailscaleConnectionManager));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _shutdownStarted = true;
        _lifetimeCancellation.Cancel();
        StopMonitor();
        UnsubscribeSystemEvents();
        lock (_sync) _activeConnection?.Cancel();
        CleanupOwnedResources();
    }
}