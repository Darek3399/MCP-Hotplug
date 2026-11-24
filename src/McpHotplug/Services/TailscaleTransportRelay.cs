using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace McpHotplug.Services;

internal enum TailscaleRouteKind
{
    Direct = 0,
    DirectTlsRecordVer = 1,
    DirectTlsSplit = 2,
    DirectTcpSplit = 3,
    HttpProxy = 4,
    Socks5Proxy = 5
}

internal sealed class TailscaleRoute : IEquatable<TailscaleRoute>
{
    public static readonly TailscaleRoute Direct = new(TailscaleRouteKind.Direct, string.Empty, 0, "direct");
    public static readonly TailscaleRoute DirectTlsRecordVer = new(TailscaleRouteKind.DirectTlsRecordVer, string.Empty, 0, "direct (TLS-ver DPI-safe)");
    public static readonly TailscaleRoute DirectTlsSplit = new(TailscaleRouteKind.DirectTlsSplit, string.Empty, 0, "direct (TLS-split DPI-safe)");
    public static readonly TailscaleRoute DirectTcpSplit = new(TailscaleRouteKind.DirectTcpSplit, string.Empty, 0, "direct (TCP-split DPI-safe)");

    public TailscaleRoute(TailscaleRouteKind kind, string host, int port, string displayName)
    {
        Kind = kind;
        Host = host ?? string.Empty;
        Port = port;
        DisplayName = displayName;
    }

    public TailscaleRouteKind Kind { get; }
    public string Host { get; }
    public int Port { get; }
    public string DisplayName { get; }

    public bool IsDirectFamily =>
        Kind == TailscaleRouteKind.Direct ||
        Kind == TailscaleRouteKind.DirectTlsRecordVer ||
        Kind == TailscaleRouteKind.DirectTlsSplit ||
        Kind == TailscaleRouteKind.DirectTcpSplit;

    public bool IsDpiSafeDirect =>
        Kind == TailscaleRouteKind.DirectTlsRecordVer ||
        Kind == TailscaleRouteKind.DirectTlsSplit ||
        Kind == TailscaleRouteKind.DirectTcpSplit;

    public int PriorityTier => Kind switch
    {
        TailscaleRouteKind.Direct => 0,
        TailscaleRouteKind.HttpProxy => 1,
        TailscaleRouteKind.Socks5Proxy => 1,
        TailscaleRouteKind.DirectTlsRecordVer => 2,
        _ => 3
    };

    public string Key => IsDirectFamily
        ? Kind.ToString().ToLowerInvariant()
        : $"{Kind.ToString().ToLowerInvariant()}://{Host.ToLowerInvariant()}:{Port}";

    public bool Equals(TailscaleRoute? other) =>
        other != null && string.Equals(Key, other.Key, StringComparison.OrdinalIgnoreCase);

    public override bool Equals(object? obj) => Equals(obj as TailscaleRoute);
    public override int GetHashCode() => StringComparer.OrdinalIgnoreCase.GetHashCode(Key);
    public override string ToString() => DisplayName;
}

internal sealed class TailscaleControlplaneFailureEventArgs : EventArgs
{
    public TailscaleControlplaneFailureEventArgs(TailscaleRoute route, string host, string reason, long bytesUp, long bytesDown)
    {
        Route = route;
        Host = host;
        Reason = reason;
        BytesUp = bytesUp;
        BytesDown = bytesDown;
    }

    public TailscaleRoute Route { get; }
    public string Host { get; }
    public string Reason { get; }
    public long BytesUp { get; }
    public long BytesDown { get; }
}

internal enum TailscaleFailureCause
{
    None = 0,
    NoInternet = 1,
    LocalDpiTool = 2,
    IspSniBlock = 3,
    Port443Blocked = 4,
    Unknown = 5
}

internal sealed class TailscaleRouteProbeResult
{
    public bool Success { get; set; }
    public TailscaleRoute? WinningRoute { get; set; }
    public int LatencyMs { get; set; }
    public List<TailscaleRoute> TestedRoutes { get; set; } = new();
    public TailscaleFailureCause FailureCause { get; set; } = TailscaleFailureCause.None;
    public string DiagnosticMessage { get; set; } = string.Empty;
    public string UserMessage { get; set; } = string.Empty;
}

internal enum PublicDnsState
{
    Resolved = 0,
    NxDomain = 1,
    Unknown = 2
}

/// <summary>
/// Discovers all active system/environment proxy routes (HTTP CONNECT & SOCKS5),
/// runs full TLS+HTTP controlplane route races (analogous to roots-filter.js),
/// classifies Direct failures (Zapret/winws, ISP DPI, Firewall, Offline),
/// and verifies public *.ts.net DNS propagation.
/// </summary>
internal static class TailscaleNetworkProbe
{
    public const string ControlplaneHost = "controlplane.tailscale.com";
    public const string ControlplaneKeyPath = "/key?v=148";
    public const int ControlplanePort = 443;

    private static readonly string[] DpiProcessNames =
    {
        "winws", "winws2", "goodbyedpi", "zapret", "ciadpi", "byedpi", "spoofdpi", "powertunnel"
    };

    public static List<TailscaleRoute> DiscoverCandidateRoutes()
    {
        var routes = new List<TailscaleRoute>
        {
            TailscaleRoute.Direct,
            TailscaleRoute.DirectTlsRecordVer,
            TailscaleRoute.DirectTlsSplit,
            TailscaleRoute.DirectTcpSplit
        };
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            TailscaleRoute.Direct.Key,
            TailscaleRoute.DirectTlsRecordVer.Key,
            TailscaleRoute.DirectTlsSplit.Key,
            TailscaleRoute.DirectTcpSplit.Key
        };

        void TryAdd(TailscaleRoute? route)
        {
            if (route == null) return;
            if (!route.IsDirectFamily && IsSelfRelayEndpoint(route.Host, route.Port))
                return;
            if (seen.Add(route.Key))
                routes.Add(route);
        }

        // 1. Fresh read from HKCU WinINET settings (bypasses .NET process proxy cache & supports socks=).
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (key != null)
            {
                var enabledObj = key.GetValue("ProxyEnable");
                var proxyEnabled = enabledObj is int i && i != 0;
                var proxyServer = key.GetValue("ProxyServer") as string;
                var proxyOverride = key.GetValue("ProxyOverride") as string;

                if (proxyEnabled && !string.IsNullOrWhiteSpace(proxyServer) && !IsControlplaneBypassed(proxyOverride))
                {
                    foreach (var parsed in ParseWinInetProxyServer(proxyServer!))
                        TryAdd(parsed);
                }
            }
        }
        catch { }

        // 2. System web proxy (handles PAC / AutoConfigURL / WPAD).
        try
        {
            var probeUri = new Uri("https://" + ControlplaneHost + ControlplaneKeyPath);
            var sysProxy = WebRequest.GetSystemWebProxy();
            if (sysProxy != null && !sysProxy.IsBypassed(probeUri))
            {
                var proxyUri = sysProxy.GetProxy(probeUri);
                if (proxyUri != null && !proxyUri.Equals(probeUri))
                    TryAdd(ParseProxyUri(proxyUri.AbsoluteUri));
            }
        }
        catch { }

        // 3. Process / User / Machine environment variables.
        foreach (var target in new[] { EnvironmentVariableTarget.Process, EnvironmentVariableTarget.User, EnvironmentVariableTarget.Machine })
        {
            foreach (var varName in new[] { "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy" })
            {
                try
                {
                    var val = Environment.GetEnvironmentVariable(varName, target);
                    if (!string.IsNullOrWhiteSpace(val))
                        TryAdd(ParseProxyUri(val!));
                }
                catch { }
            }
        }

        return routes;
    }

    public static bool IsSelfRelayEndpoint(string host, int port)
    {
        if (port != TailscaleSmartRelay.RelayPort) return false;
        var h = (host ?? string.Empty).Trim().ToLowerInvariant();
        return h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]";
    }

    public static async Task<TailscaleRouteProbeResult> RaceBestRouteAsync(
        TailscaleRoute? preferredRoute,
        bool classifyOnFailure,
        CancellationToken cancellationToken,
        ISet<string>? excludedRouteKeys = null)
    {
        var candidates = DiscoverCandidateRoutes();
        if (preferredRoute != null && !candidates.Contains(preferredRoute))
        {
            if (preferredRoute.IsDirectFamily ||
                !IsSelfRelayEndpoint(preferredRoute.Host, preferredRoute.Port))
            {
                candidates.Insert(0, preferredRoute);
            }
        }

        if (excludedRouteKeys != null && excludedRouteKeys.Count > 0)
            candidates = candidates.Where(r => !excludedRouteKeys.Contains(r.Key)).ToList();

        if (candidates.Count == 0)
        {
            return new TailscaleRouteProbeResult
            {
                Success = false,
                FailureCause = TailscaleFailureCause.Unknown,
                DiagnosticMessage = "All candidate routes were excluded after daemon timeout.",
                UserMessage = I18n.Tr(
                    "Ни один маршрут не позволил Tailscale выйти в сеть. Повторная проверка через 10 сек…",
                    "No route allowed Tailscale to come online. Retrying in 10s…")
            };
        }

        var errors = new List<string>();
        if (ErrorLog.Enabled)
        {
            var candText = string.Join(", ", candidates.Select(c => c.DisplayName));
            var exclText = excludedRouteKeys != null && excludedRouteKeys.Count > 0
                ? string.Join(", ", excludedRouteKeys)
                : "none";
            ErrorLog.LogConnection($"[Tailscale][Probe] Starting route race: candidates=[{candText}], preferred={preferredRoute?.DisplayName ?? "none"}, excluded=[{exclText}]");
        }

        // Race ALL candidates in parallel from t=0 with strict priority tiers:
        // Tier 0: Direct -> Tier 1: VPN/System proxies -> Tier 2: DirectTlsRecordVer (single-segment 0x0304) -> Tier 3: Split fallbacks.
        // This ensures instant connection without 4.5s stage stalls while always preferring Direct/VPN when healthy.
        var winner = await RunParallelRaceBatchAsync(candidates, 4500, errors, cancellationToken).ConfigureAwait(false);
        if (winner != null)
        {
            if (ErrorLog.Enabled)
            {
                var errSuffix = errors.Count > 0 ? " | other errors: " + string.Join("; ", errors) : string.Empty;
                ErrorLog.LogConnection($"[Tailscale][Probe] Parallel race winner: {winner.Value.Route} ({winner.Value.LatencyMs} ms){errSuffix}");
            }
            return new TailscaleRouteProbeResult
            {
                Success = true,
                WinningRoute = winner.Value.Route,
                LatencyMs = winner.Value.LatencyMs,
                TestedRoutes = candidates,
                DiagnosticMessage = $"Route {winner.Value.Route} won parallel race in {winner.Value.LatencyMs} ms."
            };
        }

        cancellationToken.ThrowIfCancellationRequested();

        var result = new TailscaleRouteProbeResult
        {
            Success = false,
            TestedRoutes = candidates,
            DiagnosticMessage = string.Join(" | ", errors)
        };

        if (classifyOnFailure)
        {
            var diagnosis = await ClassifyDirectFailureAsync(cancellationToken).ConfigureAwait(false);
            result.FailureCause = diagnosis.Cause;
            result.UserMessage = diagnosis.UserMessage;
            result.DiagnosticMessage = diagnosis.Detail + (string.IsNullOrWhiteSpace(result.DiagnosticMessage) ? string.Empty : " | " + result.DiagnosticMessage);
        }
        else
        {
            result.FailureCause = TailscaleFailureCause.Unknown;
            result.UserMessage = I18n.Tr(
                "Нет связи с серверами Tailscale. Повторная проверка каждые 10 сек…",
                "Cannot reach Tailscale servers. Retrying every 10s…");
        }

        if (ErrorLog.Enabled)
            ErrorLog.LogConnection($"[Tailscale][Probe] All routes failed. Cause={result.FailureCause}. Detail={result.DiagnosticMessage}");

        return result;
    }

    private static async Task<(TailscaleRoute Route, int LatencyMs)?> RunParallelRaceBatchAsync(
        List<TailscaleRoute> batch,
        int timeoutMs,
        List<string> errors,
        CancellationToken cancellationToken)
    {
        using var raceCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var sw = Stopwatch.StartNew();
        var pending = new Dictionary<Task<(TailscaleRoute Route, bool Ok, int LatencyMs, string Error)>, TailscaleRoute>();
        foreach (var route in batch)
        {
            pending[ProbeRouteEntryAsync(route, timeoutMs, raceCts.Token)] = route;
        }

        (TailscaleRoute Route, int LatencyMs)? bestWinner = null;
        Task? tierGraceTask = null;
        var graceForTier = int.MaxValue;

        while (pending.Count > 0)
        {
            Task finished;
            if (tierGraceTask != null)
            {
                var waitList = new List<Task>(pending.Count + 1);
                waitList.AddRange(pending.Keys);
                waitList.Add(tierGraceTask);
                finished = await Task.WhenAny(waitList).ConfigureAwait(false);
                if (finished == tierGraceTask)
                {
                    raceCts.Cancel();
                    return bestWinner;
                }
            }
            else
            {
                finished = await Task.WhenAny(pending.Keys).ConfigureAwait(false);
            }

            var probeTask = (Task<(TailscaleRoute Route, bool Ok, int LatencyMs, string Error)>)finished;
            pending.Remove(probeTask);

            (TailscaleRoute Route, bool Ok, int LatencyMs, string Error) outcome;
            try
            {
                outcome = await probeTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                errors.Add(ex.Message);
                outcome = default;
            }

            if (outcome.Route != null)
            {
                if (outcome.Ok)
                {
                    if (bestWinner == null || outcome.Route.PriorityTier < bestWinner.Value.Route.PriorityTier)
                        bestWinner = (outcome.Route, outcome.LatencyMs);
                }
                else
                {
                    errors.Add($"{outcome.Route}: {outcome.Error}");
                }
            }

            if (bestWinner != null)
            {
                var bestTier = bestWinner.Value.Route.PriorityTier;
                var higherTierPending = pending.Values.Any(r => r.PriorityTier < bestTier);
                if (!higherTierPending)
                {
                    raceCts.Cancel();
                    return bestWinner;
                }

                if (tierGraceTask == null || bestTier < graceForTier)
                {
                    graceForTier = bestTier;
                    var targetWindowMs = bestTier switch
                    {
                        1 => 900,  // VPN proxy waiting briefly for Direct
                        2 => 1200, // Single-segment TLS-ver DPI-safe waiting briefly for Direct/VPN
                        _ => 1400  // Split fallbacks waiting briefly for Direct/VPN/TLS-ver
                    };
                    var graceMs = Math.Max(150, targetWindowMs - (int)sw.ElapsedMilliseconds);
                    tierGraceTask = Task.Delay(graceMs, cancellationToken);
                }
            }
        }

        return bestWinner;
    }

    private static async Task<(TailscaleRoute Route, bool Ok, int LatencyMs, string Error)> ProbeRouteEntryAsync(
        TailscaleRoute route,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        var probe = await ProbeControlplaneAsync(route, timeoutMs, cancellationToken).ConfigureAwait(false);
        return (route, probe.Ok, probe.LatencyMs, probe.Error);
    }

    /// <summary>
    /// Full end-to-end TLS (real SNI) + multi-request HTTP/1.1 keep-alive probe to controlplane.tailscale.com/key?v=148.
    /// Sending 3 sequential requests over the same TLS session guarantees >= 5 client packets on the wire,
    /// reliably detecting ISP/TSPU post-handshake blackholes (e.g. drops on packet #5 for split ClientHello).
    /// </summary>
    public static async Task<(bool Ok, int LatencyMs, string Error)> ProbeControlplaneAsync(
        TailscaleRoute route,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        const int probeRequestCount = 3;
        var sw = Stopwatch.StartNew();
        TcpClient? client = null;
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(timeoutMs);

            client = await OpenTunnelStreamAsync(route, ControlplaneHost, ControlplanePort, timeoutCts.Token).ConfigureAwait(false);
            Stream transportStream = TailscaleTlsFragmenter.RequiresDpiTransform(route.Kind)
                ? (Stream)new DpiSafeTunnelStream(client.GetStream(), route.Kind)
                : client.GetStream();
            using var ssl = new SslStream(transportStream, false);
            using (timeoutCts.Token.Register(() => { try { client.Close(); } catch { } }))
            {
                await ssl.AuthenticateAsClientAsync(
                    ControlplaneHost,
                    null,
                    SslProtocols.Tls12 | (SslProtocols)0x3000 /* Tls13 if supported by OS */,
                    false).ConfigureAwait(false);

                for (var reqNum = 1; reqNum <= probeRequestCount; reqNum++)
                {
                    var connHeader = reqNum < probeRequestCount ? "keep-alive" : "close";
                    var requestBytes = Encoding.ASCII.GetBytes(
                        $"GET {ControlplaneKeyPath} HTTP/1.1\r\n" +
                        $"Host: {ControlplaneHost}\r\n" +
                        "User-Agent: MCP-Hotplug-Probe/1.0\r\n" +
                        $"Connection: {connHeader}\r\n\r\n");
                    await ssl.WriteAsync(requestBytes, 0, requestBytes.Length).ConfigureAwait(false);
                    await ssl.FlushAsync().ConfigureAwait(false);

                    var resp = await ReadHttp200AndDrainAsync(ssl, timeoutCts.Token).ConfigureAwait(false);
                    if (!resp.Ok)
                        return (false, (int)sw.ElapsedMilliseconds, $"Req #{reqNum} failed: {resp.StatusLine}");

                    if (resp.ConnectionClose && reqNum < probeRequestCount)
                        break;
                }

                return (true, (int)sw.ElapsedMilliseconds, string.Empty);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return (false, (int)sw.ElapsedMilliseconds, ex.Message);
        }
        finally
        {
            try { client?.Close(); } catch { }
            try { client?.Dispose(); } catch { }
        }
    }

    private static async Task<(bool Ok, string StatusLine, bool ConnectionClose)> ReadHttp200AndDrainAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var headerBlock = await ReadHttpHeaderBlockAsync(stream, 16384, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(headerBlock))
            return (false, "<empty>", true);

        var firstLineEnd = headerBlock.IndexOf("\r\n", StringComparison.Ordinal);
        var statusLine = firstLineEnd >= 0 ? headerBlock.Substring(0, firstLineEnd) : headerBlock;
        var ok = Regex.IsMatch(statusLine, @"^HTTP/1\.[01]\s+200\b", RegexOptions.IgnoreCase);
        if (!ok)
            return (false, statusLine, true);

        var connectionClose = Regex.IsMatch(headerBlock, @"(?im)^Connection:\s*.*\bclose\b");
        var isChunked = Regex.IsMatch(headerBlock, @"(?im)^Transfer-Encoding:\s*.*\bchunked\b");
        var clMatch = Regex.Match(headerBlock, @"(?im)^Content-Length:\s*(\d+)\s*$");

        if (clMatch.Success && int.TryParse(clMatch.Groups[1].Value, out var contentLength) && contentLength > 0)
        {
            var remaining = contentLength;
            var scratch = new byte[Math.Min(remaining, 4096)];
            while (remaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var read = await stream.ReadAsync(scratch, 0, Math.Min(remaining, scratch.Length)).ConfigureAwait(false);
                if (read <= 0)
                    return (false, "EOF reading body", true);
                remaining -= read;
            }
        }
        else if (isChunked)
        {
            var scratch = new byte[4096];
            while (true)
            {
                var sizeLine = await ReadStatusLineAsync(stream, cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(sizeLine))
                    return (false, "EOF reading chunk size", true);
                var semi = sizeLine!.IndexOf(';');
                var hex = (semi >= 0 ? sizeLine.Substring(0, semi) : sizeLine).Trim();
                if (!int.TryParse(hex, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var chunkLen) || chunkLen < 0)
                    return (false, "Invalid chunk size: " + sizeLine, true);
                if (chunkLen == 0)
                {
                    // Drain trailing CRLF / empty trailer line.
                    await ReadStatusLineAsync(stream, cancellationToken).ConfigureAwait(false);
                    break;
                }
                var rem = chunkLen + 2; // chunk payload + CRLF
                while (rem > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var r = await stream.ReadAsync(scratch, 0, Math.Min(rem, scratch.Length)).ConfigureAwait(false);
                    if (r <= 0) return (false, "EOF reading chunk payload", true);
                    rem -= r;
                }
            }
        }

        return (true, statusLine, connectionClose);
    }

    public static async Task<TcpClient> OpenTunnelStreamAsync(
        TailscaleRoute route,
        string targetHost,
        int targetPort,
        CancellationToken cancellationToken)
    {
        if (route.IsDirectFamily)
            return await ConnectTcpAsync(targetHost, targetPort, cancellationToken).ConfigureAwait(false);

        if (route.Kind == TailscaleRouteKind.HttpProxy)
        {
            var proxyClient = await ConnectTcpAsync(route.Host, route.Port, cancellationToken).ConfigureAwait(false);
            try
            {
                var stream = proxyClient.GetStream();
                var hostHeader = targetHost.Contains(":") && !targetHost.StartsWith("[", StringComparison.Ordinal)
                    ? $"[{targetHost}]:{targetPort}"
                    : $"{targetHost}:{targetPort}";
                var req = Encoding.ASCII.GetBytes(
                    $"CONNECT {hostHeader} HTTP/1.1\r\n" +
                    $"Host: {hostHeader}\r\n" +
                    "Proxy-Connection: Keep-Alive\r\n\r\n");

                using (cancellationToken.Register(() => { try { proxyClient.Close(); } catch { } }))
                {
                    await stream.WriteAsync(req, 0, req.Length).ConfigureAwait(false);
                    await stream.FlushAsync().ConfigureAwait(false);
                    var headerBlock = await ReadHttpHeaderBlockAsync(stream, 16384, cancellationToken).ConfigureAwait(false);
                    var firstLineEnd = headerBlock.IndexOf("\r\n", StringComparison.Ordinal);
                    var statusLine = firstLineEnd >= 0 ? headerBlock.Substring(0, firstLineEnd) : headerBlock;
                    if (!Regex.IsMatch(statusLine, @"^HTTP/1\.[01]\s+200\b", RegexOptions.IgnoreCase))
                        throw new IOException("HTTP proxy CONNECT rejected: " + statusLine);
                }
                return proxyClient;
            }
            catch
            {
                try { proxyClient.Close(); } catch { }
                try { proxyClient.Dispose(); } catch { }
                throw;
            }
        }

        if (route.Kind == TailscaleRouteKind.Socks5Proxy)
        {
            var proxyClient = await ConnectTcpAsync(route.Host, route.Port, cancellationToken).ConfigureAwait(false);
            try
            {
                var stream = proxyClient.GetStream();
                using (cancellationToken.Register(() => { try { proxyClient.Close(); } catch { } }))
                {
                    // SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
                    await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, 0, 3).ConfigureAwait(false);
                    var greetResp = await ReadExactAsync(stream, 2).ConfigureAwait(false);
                    if (greetResp[0] != 0x05 || greetResp[1] != 0x00)
                        throw new IOException($"SOCKS5 auth negotiation failed (ver={greetResp[0]}, method={greetResp[1]}).");

                    // Build CONNECT request (RFC 1928)
                    using var reqBuf = new MemoryStream();
                    reqBuf.WriteByte(0x05); // VER
                    reqBuf.WriteByte(0x01); // CMD = CONNECT
                    reqBuf.WriteByte(0x00); // RSV

                    var cleanHost = targetHost.Trim('[', ']');
                    if (IPAddress.TryParse(cleanHost, out var ip))
                    {
                        var ipBytes = ip.GetAddressBytes();
                        reqBuf.WriteByte(ip.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04);
                        reqBuf.Write(ipBytes, 0, ipBytes.Length);
                    }
                    else
                    {
                        var hostBytes = Encoding.ASCII.GetBytes(cleanHost);
                        if (hostBytes.Length > 255) throw new IOException("Target hostname too long for SOCKS5.");
                        reqBuf.WriteByte(0x03); // ATYP = DOMAINNAME (DNS resolved by VPN side!)
                        reqBuf.WriteByte((byte)hostBytes.Length);
                        reqBuf.Write(hostBytes, 0, hostBytes.Length);
                    }

                    reqBuf.WriteByte((byte)((targetPort >> 8) & 0xFF));
                    reqBuf.WriteByte((byte)(targetPort & 0xFF));

                    var packet = reqBuf.ToArray();
                    await stream.WriteAsync(packet, 0, packet.Length).ConfigureAwait(false);
                    await stream.FlushAsync().ConfigureAwait(false);

                    var replyHead = await ReadExactAsync(stream, 4).ConfigureAwait(false);
                    if (replyHead[0] != 0x05 || replyHead[1] != 0x00)
                        throw new IOException($"SOCKS5 CONNECT failed with reply code 0x{replyHead[1]:X2}.");

                    // Consume BND.ADDR + BND.PORT
                    if (replyHead[3] == 0x01)
                        await ReadExactAsync(stream, 4 + 2).ConfigureAwait(false);
                    else if (replyHead[3] == 0x04)
                        await ReadExactAsync(stream, 16 + 2).ConfigureAwait(false);
                    else if (replyHead[3] == 0x03)
                    {
                        var lenByte = await ReadExactAsync(stream, 1).ConfigureAwait(false);
                        await ReadExactAsync(stream, lenByte[0] + 2).ConfigureAwait(false);
                    }
                }
                return proxyClient;
            }
            catch
            {
                try { proxyClient.Close(); } catch { }
                try { proxyClient.Dispose(); } catch { }
                throw;
            }
        }

        throw new NotSupportedException("Unsupported Tailscale route kind: " + route.Kind);
    }

    public static async Task<PublicDnsState> CheckPublicDnsAsync(
        string hostname,
        TailscaleRoute route,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(hostname))
            return PublicDnsState.Unknown;

        var cleanHost = hostname.Trim().TrimEnd('.');

        // 1. Fast time-bounded local OS DNS check.
        try
        {
            var dnsTask = Dns.GetHostAddressesAsync(cleanHost);
            var completed = await Task.WhenAny(dnsTask, Task.Delay(1000, cancellationToken)).ConfigureAwait(false);
            if (completed == dnsTask)
            {
                var localAddresses = await dnsTask.ConfigureAwait(false);
                if (localAddresses != null && localAddresses.Length > 0)
                    return PublicDnsState.Resolved;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { }

        // 2. Parallel authoritative DoH race over the winning route (and Direct fallback for DPI-safe direct routes).
        using var dohRaceCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var dohTasks = new List<Task<PublicDnsState>>
        {
            QueryDohAsync("dns.google", $"/resolve?name={Uri.EscapeDataString(cleanHost)}&type=A", route, dohRaceCts.Token),
            QueryDohAsync("cloudflare-dns.com", $"/dns-query?name={Uri.EscapeDataString(cleanHost)}&type=A", route, dohRaceCts.Token)
        };
        if (route.IsDpiSafeDirect)
        {
            dohTasks.Add(QueryDohAsync("dns.google", $"/resolve?name={Uri.EscapeDataString(cleanHost)}&type=A", TailscaleRoute.Direct, dohRaceCts.Token));
            dohTasks.Add(QueryDohAsync("cloudflare-dns.com", $"/dns-query?name={Uri.EscapeDataString(cleanHost)}&type=A", TailscaleRoute.Direct, dohRaceCts.Token));
        }

        var fallbackState = PublicDnsState.Unknown;
        while (dohTasks.Count > 0)
        {
            var finished = await Task.WhenAny(dohTasks).ConfigureAwait(false);
            dohTasks.Remove(finished);
            PublicDnsState state;
            try { state = await finished.ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch { continue; }

            if (state == PublicDnsState.Resolved)
            {
                dohRaceCts.Cancel();
                return PublicDnsState.Resolved;
            }
            if (state == PublicDnsState.NxDomain)
                fallbackState = PublicDnsState.NxDomain;
        }

        return fallbackState;
    }

    private static async Task<PublicDnsState> QueryDohAsync(
        string dohHost,
        string dohPath,
        TailscaleRoute route,
        CancellationToken cancellationToken)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(3000);
            using var client = await OpenTunnelStreamAsync(route, dohHost, 443, cts.Token).ConfigureAwait(false);
            Stream dohStream = TailscaleTlsFragmenter.RequiresDpiTransform(route.Kind)
                ? (Stream)new DpiSafeTunnelStream(client.GetStream(), route.Kind)
                : client.GetStream();
            using var ssl = new SslStream(dohStream, false);
            using (cts.Token.Register(() => { try { client.Close(); } catch { } }))
            {
                await ssl.AuthenticateAsClientAsync(dohHost, null, SslProtocols.Tls12 | (SslProtocols)0x3000, false).ConfigureAwait(false);
                var req = Encoding.ASCII.GetBytes(
                    $"GET {dohPath} HTTP/1.1\r\n" +
                    $"Host: {dohHost}\r\n" +
                    "Accept: application/dns-json\r\n" +
                    "Connection: close\r\n\r\n");
                await ssl.WriteAsync(req, 0, req.Length).ConfigureAwait(false);
                await ssl.FlushAsync().ConfigureAwait(false);

                using var reader = new StreamReader(ssl, Encoding.UTF8);
                var full = await reader.ReadToEndAsync().ConfigureAwait(false);
                var bodyIdx = full.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                var body = bodyIdx >= 0 ? full.Substring(bodyIdx + 4) : full;

                if (Regex.IsMatch(body, @"""Status""\s*:\s*3\b"))
                    return PublicDnsState.NxDomain;

                if (Regex.IsMatch(body, @"""Status""\s*:\s*0\b") &&
                    body.IndexOf("\"Answer\"", StringComparison.OrdinalIgnoreCase) >= 0)
                    return PublicDnsState.Resolved;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { }

        return PublicDnsState.Unknown;
    }

    private static async Task<(TailscaleFailureCause Cause, string UserMessage, string Detail)> ClassifyDirectFailureAsync(
        CancellationToken cancellationToken)
    {
        // Step 1: Check general internet reachability via 1.1.1.1:443
        var internetOk = await TestTcpDirectAsync("1.1.1.1", 443, 2500, cancellationToken).ConfigureAwait(false);
        if (!internetOk)
        {
            return (
                TailscaleFailureCause.NoInternet,
                I18n.Tr(
                    "Нет подключения к интернету. Повторная проверка каждые 10 сек…",
                    "No internet connection. Retrying every 10s…"),
                "TCP 1.1.1.1:443 unreachable.");
        }

        // Step 2: Resolve controlplane.tailscale.com and test raw TCP :443
        string? targetIp = null;
        try
        {
            var ips = await Dns.GetHostAddressesAsync(ControlplaneHost).ConfigureAwait(false);
            targetIp = ips.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString()
                       ?? ips.FirstOrDefault()?.ToString();
        }
        catch { }

        if (string.IsNullOrWhiteSpace(targetIp))
        {
            return (
                TailscaleFailureCause.NoInternet,
                I18n.Tr(
                    "Не удалось разрешить DNS controlplane.tailscale.com. Проверьте сеть или включите VPN. Повтор через 10 сек…",
                    "Failed to resolve controlplane.tailscale.com DNS. Check network or enable VPN. Retrying in 10s…"),
                "DNS resolution failed for controlplane.tailscale.com.");
        }

        var tcpOk = await TestTcpDirectAsync(targetIp!, ControlplanePort, 2500, cancellationToken).ConfigureAwait(false);
        if (!tcpOk)
        {
            return (
                TailscaleFailureCause.Port443Blocked,
                I18n.Tr(
                    "Заблокирован доступ к серверам Tailscale (порт 443). Проверьте фаервол или включите VPN. Повтор через 10 сек…",
                    "Access to Tailscale servers (port 443) is blocked. Check firewall or enable VPN. Retrying in 10s…"),
                $"Internet OK, but TCP {targetIp}:443 failed.");
        }

        // Step 3: SNI A/B test on the exact same IP (matches our proven PowerShell diagnostic!)
        var emptySniTask = TestTlsSniAsync(targetIp!, ControlplanePort, string.Empty, 3000, cancellationToken);
        var fakeSniTask = TestTlsSniAsync(targetIp!, ControlplanePort, "example.com", 3000, cancellationToken);
        await Task.WhenAll(emptySniTask, fakeSniTask).ConfigureAwait(false);

        var emptySniReplied = emptySniTask.Result;
        var fakeSniReplied = fakeSniTask.Result;
        var dpiTool = DetectRunningDpiProcess();

        if (emptySniReplied && !fakeSniReplied && !string.IsNullOrWhiteSpace(dpiTool))
        {
            return (
                TailscaleFailureCause.LocalDpiTool,
                I18n.Tr(
                    $"Локальный DPI-обходчик ({dpiTool}) блокирует TLS к Tailscale. Включите VPN или добавьте controlplane.tailscale.com в исключения. Повтор через 10 сек…",
                    $"Local DPI bypass tool ({dpiTool}) is breaking TLS to Tailscale. Enable VPN or exclude controlplane.tailscale.com. Retrying in 10s…"),
                $"TCP OK, empty SNI OK, fake SNI timed out, running DPI process: {dpiTool}.");
        }

        if (fakeSniReplied || emptySniReplied)
        {
            return (
                TailscaleFailureCause.IspSniBlock,
                I18n.Tr(
                    "Провайдер/DPI блокирует controlplane.tailscale.com. Включите VPN (подойдёт режим прокси или TUN). Повтор через 10 сек…",
                    "ISP/DPI is blocking controlplane.tailscale.com. Enable VPN (system proxy or TUN mode). Retrying in 10s…"),
                $"TCP OK, fakeSni={fakeSniReplied}, emptySni={emptySniReplied}, real SNI timed out.");
        }

        return (
            TailscaleFailureCause.Unknown,
            I18n.Tr(
                "Нет связи с controlplane.tailscale.com. Включите VPN или проверьте сеть. Повтор через 10 сек…",
                "Cannot complete TLS handshake with controlplane.tailscale.com. Enable VPN or check network. Retrying in 10s…"),
            $"TCP {targetIp}:443 OK, all TLS handshakes failed.");
    }

    private static string? DetectRunningDpiProcess()
    {
        foreach (var name in DpiProcessNames)
        {
            try
            {
                var procs = Process.GetProcessesByName(name);
                if (procs.Length > 0)
                {
                    foreach (var p in procs) p.Dispose();
                    return name + ".exe";
                }
            }
            catch { }
        }
        return null;
    }

    private static async Task<bool> TestTcpDirectAsync(string host, int port, int timeoutMs, CancellationToken cancellationToken)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);
            using var client = await ConnectTcpAsync(host, port, cts.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> TestTlsSniAsync(string ip, int port, string sni, int timeoutMs, CancellationToken cancellationToken)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);
            using var client = await ConnectTcpAsync(ip, port, cts.Token).ConfigureAwait(false);
            using var ssl = new SslStream(client.GetStream(), false, (_, _, _, _) => true);
            using (cts.Token.Register(() => { try { client.Close(); } catch { } }))
            {
                await ssl.AuthenticateAsClientAsync(sni, null, SslProtocols.Tls12, false).ConfigureAwait(false);
                return true;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (AuthenticationException)
        {
            // Server replied with a TLS alert/handshake response rather than silent DPI drop.
            return true;
        }
        catch
        {
            return false;
        }
    }

    internal static void EnableTcpKeepAlive(TcpClient client)
    {
        try
        {
            var vals = new byte[12];
            BitConverter.GetBytes(1u).CopyTo(vals, 0);
            BitConverter.GetBytes(20000u).CopyTo(vals, 4);
            BitConverter.GetBytes(5000u).CopyTo(vals, 8);
            client.Client.IOControl(IOControlCode.KeepAliveValues, vals, null);
        }
        catch { }
    }

    private static async Task<TcpClient> ConnectTcpAsync(string host, int port, CancellationToken cancellationToken)
    {
        var client = new TcpClient { NoDelay = true };
        try
        {
            using (cancellationToken.Register(() => { try { client.Close(); } catch { } }))
            {
                await client.ConnectAsync(host, port).ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();
            EnableTcpKeepAlive(client);
            return client;
        }
        catch
        {
            try { client.Close(); } catch { }
            try { client.Dispose(); } catch { }
            throw;
        }
    }

    private static List<TailscaleRoute> ParseWinInetProxyServer(string proxyServer)
    {
        var results = new List<TailscaleRoute>();
        var trimmed = proxyServer.Trim();
        if (string.IsNullOrWhiteSpace(trimmed)) return results;

        if (!trimmed.Contains("="))
        {
            var single = ParseProxyUri(trimmed);
            if (single != null) results.Add(single);
            return results;
        }

        // Format: "http=127.0.0.1:10809;https=127.0.0.1:10809;socks=127.0.0.1:10808"
        var parts = trimmed.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
        // Prefer https -> http -> socks
        string? httpsVal = null, httpVal = null, socksVal = null;
        foreach (var rawPart in parts)
        {
            var eq = rawPart.IndexOf('=');
            if (eq <= 0) continue;
            var proto = rawPart.Substring(0, eq).Trim().ToLowerInvariant();
            var addr = rawPart.Substring(eq + 1).Trim();
            if (proto == "https") httpsVal = addr;
            else if (proto == "http") httpVal = addr;
            else if (proto == "socks" || proto == "socks5") socksVal = addr;
        }

        if (!string.IsNullOrWhiteSpace(httpsVal))
        {
            var r = ParseProxyUri(httpsVal!);
            if (r != null) results.Add(r);
        }
        if (!string.IsNullOrWhiteSpace(httpVal))
        {
            var r = ParseProxyUri(httpVal!);
            if (r != null) results.Add(r);
        }
        if (!string.IsNullOrWhiteSpace(socksVal))
        {
            var normalized = socksVal!.Contains("://") ? socksVal : "socks5://" + socksVal;
            var r = ParseProxyUri(normalized);
            if (r != null) results.Add(r);
        }

        return results;
    }

    private static TailscaleRoute? ParseProxyUri(string raw)
    {
        var text = (raw ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(text)) return null;

        if (!text.Contains("://"))
            text = "http://" + text;

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri))
            return null;
        if (string.IsNullOrWhiteSpace(uri.Host) || uri.Port <= 0 || uri.Port > 65535)
            return null;

        var scheme = uri.Scheme.ToLowerInvariant();
        if (scheme == "http" || scheme == "https")
            return new TailscaleRoute(TailscaleRouteKind.HttpProxy, uri.Host, uri.Port, $"http://{uri.Host}:{uri.Port}");
        if (scheme == "socks" || scheme == "socks5" || scheme == "socks5h")
            return new TailscaleRoute(TailscaleRouteKind.Socks5Proxy, uri.Host, uri.Port, $"socks5://{uri.Host}:{uri.Port}");

        return null;
    }

    private static bool IsControlplaneBypassed(string? proxyOverride)
    {
        if (string.IsNullOrWhiteSpace(proxyOverride)) return false;
        foreach (var raw in proxyOverride!.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var pattern = raw.Trim();
            if (string.IsNullOrWhiteSpace(pattern) || pattern.Equals("<local>", StringComparison.OrdinalIgnoreCase))
                continue;
            var regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
            if (Regex.IsMatch(ControlplaneHost, regex, RegexOptions.IgnoreCase))
                return true;
        }
        return false;
    }

    internal static async Task<string> ReadHttpHeaderBlockAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        var buffer = new byte[maxBytes];
        var total = 0;
        var one = new byte[1];
        while (total < maxBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = await stream.ReadAsync(one, 0, 1).ConfigureAwait(false);
            if (read == 0) break;
            buffer[total++] = one[0];
            if (total >= 4 &&
                buffer[total - 4] == '\r' &&
                buffer[total - 3] == '\n' &&
                buffer[total - 2] == '\r' &&
                buffer[total - 1] == '\n')
            {
                return Encoding.ASCII.GetString(buffer, 0, total);
            }
        }
        return Encoding.ASCII.GetString(buffer, 0, total);
    }

    private static async Task<string?> ReadStatusLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        var sb = new StringBuilder();
        var one = new byte[1];
        while (sb.Length < 1024)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = await stream.ReadAsync(one, 0, 1).ConfigureAwait(false);
            if (read == 0) break;
            if (one[0] == '\n') break;
            if (one[0] != '\r') sb.Append((char)one[0]);
        }
        return sb.Length > 0 ? sb.ToString() : null;
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int count)
    {
        var buf = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buf, offset, count - offset).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("Unexpected EOF during proxy handshake.");
            offset += read;
        }
        return buf;
    }
}

/// <summary>
/// Universal RFC-compliant TLS ClientHello / HTTP first-packet DPI transform.
/// - DirectTlsRecordVer: patches only legacy_record_version (0x0300..0x0303 -> 0x0304) in a SINGLE TCP segment
///   (RFC 8446 §4.4.1 / §5.1). Bypasses local winws/Zapret IsTLSClientHello while preserving a complete single-record
///   ClientHello+SNI for ISP/TSPU filters that drop fragmented/multi-record TLS streams.
/// - DirectTlsSplit / DirectTcpSplit: fallback fragmentation modes for other DPI environments.
/// </summary>
internal static class TailscaleTlsFragmenter
{
    public static bool RequiresDpiTransform(TailscaleRouteKind kind) =>
        kind == TailscaleRouteKind.DirectTlsRecordVer ||
        kind == TailscaleRouteKind.DirectTlsSplit ||
        kind == TailscaleRouteKind.DirectTcpSplit;

    public static bool TryBuildRecordVerPatched(
        byte[] buffer,
        int offset,
        int count,
        out byte[] patched)
    {
        if (count >= 6 &&
            buffer[offset] == 0x16 &&
            buffer[offset + 1] == 0x03 &&
            buffer[offset + 2] <= 0x03 &&
            buffer[offset + 5] == 0x01)
        {
            patched = new byte[count];
            Buffer.BlockCopy(buffer, offset, patched, 0, count);
            patched[2] = 0x04;
            return true;
        }

        patched = Array.Empty<byte>();
        return false;
    }

    public static bool TryBuildSplitParts(
        byte[] buffer,
        int offset,
        int count,
        TailscaleRouteKind routeKind,
        out byte[] part1,
        out byte[] part2,
        out int delayMs)
    {
        part1 = Array.Empty<byte>();
        part2 = Array.Empty<byte>();
        delayMs = 15;

        if (routeKind == TailscaleRouteKind.DirectTlsRecordVer || count <= 2) return false;

        // 1. Valid 2-record TLS ClientHello fragmentation (RFC 5246 / RFC 8446).
        // Record 1 contains only 1-2 bytes of the handshake header (no SNI).
        // Record 2 never starts with HandshakeType=0x01, so packet-2 scanners skip it as well.
        if (routeKind == TailscaleRouteKind.DirectTlsSplit &&
            count >= 10 &&
            buffer[offset] == 0x16 &&
            buffer[offset + 1] == 0x03 &&
            buffer[offset + 2] <= 0x04 &&
            buffer[offset + 5] == 0x01)
        {
            var recLen = (buffer[offset + 3] << 8) | buffer[offset + 4];
            if (recLen > 2 && recLen <= 16384 && count >= 5 + recLen)
            {
                var splitAt = (recLen > 2 && buffer[offset + 7] != 0x01) ? 2 : 1;
                var part2Len = recLen - splitAt;
                var tailLen = count - (5 + recLen);

                part1 = new byte[5 + splitAt];
                part1[0] = 0x16;
                part1[1] = buffer[offset + 1];
                part1[2] = buffer[offset + 2];
                part1[3] = (byte)(splitAt >> 8);
                part1[4] = (byte)(splitAt & 0xFF);
                Buffer.BlockCopy(buffer, offset + 5, part1, 5, splitAt);

                part2 = new byte[5 + part2Len + tailLen];
                part2[0] = 0x16;
                part2[1] = buffer[offset + 1];
                part2[2] = buffer[offset + 2];
                part2[3] = (byte)(part2Len >> 8);
                part2[4] = (byte)(part2Len & 0xFF);
                Buffer.BlockCopy(buffer, offset + 5 + splitAt, part2, 5, part2Len);
                if (tailLen > 0)
                    Buffer.BlockCopy(buffer, offset + 5 + recLen, part2, 5 + part2Len, tailLen);

                delayMs = 15;
                return true;
            }
        }

        // 2. Pure TCP-level 2-byte fragmentation (leaves TLS/HTTP bytes untouched; defeats packet-1 DPI matchers).
        var isTlsClientHello = count >= 6 && buffer[offset] == 0x16 && buffer[offset + 1] == 0x03 && buffer[offset + 5] == 0x01;
        var isPlainHttp = count >= 5 && IsAsciiHttpMethodPrefix(buffer, offset);
        if (isTlsClientHello || isPlainHttp)
        {
            const int splitAt = 2;
            part1 = new byte[splitAt];
            part2 = new byte[count - splitAt];
            Buffer.BlockCopy(buffer, offset, part1, 0, splitAt);
            Buffer.BlockCopy(buffer, offset + splitAt, part2, 0, count - splitAt);
            delayMs = 20;
            return true;
        }

        return false;
    }

    public static void WriteFragmentedSync(Stream destination, byte[] buffer, int offset, int count, TailscaleRouteKind routeKind)
    {
        if (routeKind == TailscaleRouteKind.DirectTlsRecordVer)
        {
            if (TryBuildRecordVerPatched(buffer, offset, count, out var patched))
            {
                destination.Write(patched, 0, patched.Length);
                destination.Flush();
                return;
            }

            destination.Write(buffer, offset, count);
            destination.Flush();
            return;
        }

        if (TryBuildSplitParts(buffer, offset, count, routeKind, out var part1, out var part2, out var delayMs))
        {
            destination.Write(part1, 0, part1.Length);
            destination.Flush();
            Thread.Sleep(delayMs);
            destination.Write(part2, 0, part2.Length);
            destination.Flush();
            return;
        }

        destination.Write(buffer, offset, count);
        destination.Flush();
    }

    public static async Task WriteFragmentedAsync(
        Stream destination,
        byte[] buffer,
        int offset,
        int count,
        TailscaleRouteKind routeKind,
        CancellationToken cancellationToken)
    {
        if (routeKind == TailscaleRouteKind.DirectTlsRecordVer)
        {
            if (TryBuildRecordVerPatched(buffer, offset, count, out var patched))
            {
                await destination.WriteAsync(patched, 0, patched.Length, cancellationToken).ConfigureAwait(false);
                await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
                return;
            }

            await destination.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        if (TryBuildSplitParts(buffer, offset, count, routeKind, out var part1, out var part2, out var delayMs))
        {
            await destination.WriteAsync(part1, 0, part1.Length, cancellationToken).ConfigureAwait(false);
            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            await Task.Delay(delayMs, cancellationToken).ConfigureAwait(false);
            await destination.WriteAsync(part2, 0, part2.Length, cancellationToken).ConfigureAwait(false);
            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        await destination.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task<int> ForwardFirstChunkAsync(
        Stream source,
        Stream destination,
        TailscaleRouteKind routeKind,
        CancellationToken cancellationToken)
    {
        var buf = new byte[32768];
        var total = await source.ReadAsync(buf, 0, buf.Length, cancellationToken).ConfigureAwait(false);
        if (total <= 0) return 0;

        if ((routeKind == TailscaleRouteKind.DirectTlsRecordVer || routeKind == TailscaleRouteKind.DirectTlsSplit) &&
            total >= 2 && buf[0] == 0x16 && buf[1] == 0x03)
        {
            while (total < 5)
            {
                var n = await source.ReadAsync(buf, total, buf.Length - total, cancellationToken).ConfigureAwait(false);
                if (n <= 0) break;
                total += n;
            }

            if (total >= 5 && buf[2] <= 0x04)
            {
                var recLen = (buf[3] << 8) | buf[4];
                if (recLen > 0 && recLen <= 16384 && 5 + recLen <= buf.Length)
                {
                    while (total < 5 + recLen)
                    {
                        var n = await source.ReadAsync(buf, total, buf.Length - total, cancellationToken).ConfigureAwait(false);
                        if (n <= 0) break;
                        total += n;
                    }
                }
            }
        }

        await WriteFragmentedAsync(destination, buf, 0, total, routeKind, cancellationToken).ConfigureAwait(false);
        return total;
    }

    private static bool IsAsciiHttpMethodPrefix(byte[] b, int o) =>
        (b[o] == 'G' && b[o + 1] == 'E' && b[o + 2] == 'T' && b[o + 3] == ' ') ||
        (b[o] == 'P' && b[o + 1] == 'O' && b[o + 2] == 'S' && b[o + 3] == 'T') ||
        (b[o] == 'H' && b[o + 1] == 'E' && b[o + 2] == 'A' && b[o + 3] == 'D') ||
        (b[o] == 'P' && b[o + 1] == 'U' && b[o + 2] == 'T' && b[o + 3] == ' ');
}

internal sealed class DpiSafeTunnelStream : Stream
{
    private readonly Stream _inner;
    private readonly TailscaleRouteKind _routeKind;
    private bool _firstWriteDone;

    public DpiSafeTunnelStream(Stream inner, TailscaleRouteKind routeKind)
    {
        _inner = inner;
        _routeKind = routeKind;
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => _inner.CanWrite;
    public override bool CanTimeout => _inner.CanTimeout;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int ReadTimeout { get => _inner.ReadTimeout; set => _inner.ReadTimeout = value; }
    public override int WriteTimeout { get => _inner.WriteTimeout; set => _inner.WriteTimeout = value; }

    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        _inner.ReadAsync(buffer, offset, count, cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (!_firstWriteDone)
        {
            _firstWriteDone = true;
            TailscaleTlsFragmenter.WriteFragmentedSync(_inner, buffer, offset, count, _routeKind);
            return;
        }
        _inner.Write(buffer, offset, count);
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        if (!_firstWriteDone)
        {
            _firstWriteDone = true;
            await TailscaleTlsFragmenter.WriteFragmentedAsync(_inner, buffer, offset, count, _routeKind, cancellationToken).ConfigureAwait(false);
            return;
        }
        await _inner.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// Built-in local HTTP CONNECT / forward proxy on 127.0.0.1:18006 for the Windows Tailscale service.
/// Switches seamlessly between Direct, DPI-safe Direct (TLS/TCP split), HTTP Proxy, and SOCKS5 Proxy without UAC or restarting tailscaled.
/// </summary>
internal sealed class TailscaleSmartRelay : IDisposable
{
    public const int RelayPort = 18006;
    public static string RelayProxyUrl => $"http://127.0.0.1:{RelayPort}";

    private readonly object _sync = new();
    private readonly ConcurrentDictionary<long, ActiveTunnel> _activeTunnels = new();
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private TailscaleRoute _currentRoute = TailscaleRoute.Direct;
    private long _routeGeneration;
    private long _nextTunnelId;
    private int _consecutiveConnectFailures;
    private DateTime _lastFailureSignalUtc = DateTime.MinValue;
    private bool _disposed;

    public event EventHandler<string>? RouteFailureDetected;
    public event EventHandler<TailscaleControlplaneFailureEventArgs>? ControlplaneTunnelFailed;

    public TailscaleRoute CurrentRoute
    {
        get { lock (_sync) return _currentRoute; }
    }

    public bool IsRunning
    {
        get { lock (_sync) return _listener != null; }
    }

    public void EnsureStarted()
    {
        TailscaleRoute routeSnapshot;
        lock (_sync)
        {
            if (_disposed || _listener != null) return;
            var listener = new TcpListener(IPAddress.Loopback, RelayPort);
            listener.Start();
            _listener = listener;
            _cts = new CancellationTokenSource();
            routeSnapshot = _currentRoute;
            var token = _cts.Token;
            _ = Task.Run(() => AcceptLoopAsync(listener, token));
        }
        if (ErrorLog.Enabled)
            ErrorLog.LogConnection($"[Tailscale][Relay] Listening on 127.0.0.1:{RelayPort} (route={routeSnapshot})");
    }

    public bool SetRoute(TailscaleRoute nextRoute, bool abortExistingTunnels)
    {
        if (nextRoute == null) throw new ArgumentNullException(nameof(nextRoute));
        bool changed;
        TailscaleRoute prevRoute;
        lock (_sync)
        {
            prevRoute = _currentRoute;
            changed = !_currentRoute.Equals(nextRoute);
            _currentRoute = nextRoute;
            if (changed || abortExistingTunnels)
                _routeGeneration++;
            _consecutiveConnectFailures = 0;
        }

        var activeCount = _activeTunnels.Count;
        if (ErrorLog.Enabled && (changed || abortExistingTunnels))
            ErrorLog.LogConnection($"[Tailscale][Relay] SetRoute {prevRoute} -> {nextRoute} (abortExisting={abortExistingTunnels}, activeTunnels={activeCount})");

        if (changed || abortExistingTunnels)
            AbortActiveTunnels();

        return changed;
    }

    public void AbortActiveTunnels()
    {
        foreach (var kv in _activeTunnels.ToArray())
        {
            if (_activeTunnels.TryRemove(kv.Key, out var tunnel))
                tunnel.Abort();
        }
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient? client = null;
            try
            {
                client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                client.NoDelay = true;
                TailscaleNetworkProbe.EnableTcpKeepAlive(client);
                _ = Task.Run(() => HandleClientAsync(client, cancellationToken));
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch
            {
                try { client?.Dispose(); } catch { }
                if (cancellationToken.IsCancellationRequested) break;
                await Task.Delay(50).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken shutdownToken)
    {
        var tunnelId = Interlocked.Increment(ref _nextTunnelId);
        TcpClient? upstream = null;
        try
        {
            using var headerCts = CancellationTokenSource.CreateLinkedTokenSource(shutdownToken);
            headerCts.CancelAfter(10000);

            var clientStream = client.GetStream();
            var headerBlock = await TailscaleNetworkProbe
                .ReadHttpHeaderBlockAsync(clientStream, 32768, headerCts.Token)
                .ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(headerBlock))
                return;

            var firstLineEnd = headerBlock.IndexOf("\r\n", StringComparison.Ordinal);
            var requestLine = firstLineEnd >= 0 ? headerBlock.Substring(0, firstLineEnd) : headerBlock;
            var tokens = requestLine.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 2)
                return;

            var method = tokens[0].ToUpperInvariant();
            var target = tokens[1];
            TailscaleRoute route;
            long capturedGen;
            lock (_sync)
            {
                route = _currentRoute;
                capturedGen = _routeGeneration;
            }

            if (method == "CONNECT")
            {
                if (!TryParseHostPort(target, 443, out var host, out var port))
                {
                    await SendSimpleHttpResponseAsync(clientStream, "400 Bad Request").ConfigureAwait(false);
                    return;
                }

                // Never proxy loopback back through an external VPN proxy.
                var effectiveRoute = IsLoopbackHost(host) ? TailscaleRoute.Direct : route;
                var tunnel = new ActiveTunnel(client, shutdownToken);
                _activeTunnels[tunnelId] = tunnel;
                if (!IsGenerationCurrent(capturedGen))
                {
                    tunnel.Abort();
                    return;
                }

                var connectSw = Stopwatch.StartNew();
                try
                {
                    using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(tunnel.Token);
                    connectCts.CancelAfter(12000);
                    upstream = await TailscaleNetworkProbe
                        .OpenTunnelStreamAsync(effectiveRoute, host, port, connectCts.Token)
                        .ConfigureAwait(false);
                    if (tunnel.IsAborted || !IsGenerationCurrent(capturedGen))
                    {
                        tunnel.Abort();
                        return;
                    }
                    tunnel.AttachUpstream(upstream);
                    Interlocked.Exchange(ref _consecutiveConnectFailures, 0);
                }
                catch (OperationCanceledException) when (tunnel.IsAborted || shutdownToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    if (ErrorLog.Enabled)
                        ErrorLog.LogConnection($"[Tailscale][Relay] CONNECT {host}:{port} via {effectiveRoute} FAILED in {connectSw.ElapsedMilliseconds}ms: {ex.GetType().Name}: {ex.Message}");
                    await SendSimpleHttpResponseAsync(clientStream, "502 Bad Gateway").ConfigureAwait(false);
                    RecordConnectFailure(effectiveRoute, $"{host}:{port} -> {ex.Message}");
                    if (IsControlplaneHost(host))
                        RaiseControlplaneFailure(effectiveRoute, host, $"connect_failed: {ex.Message}", 0, 0);
                    return;
                }

                var stats = new TunnelStats();

                await SendSimpleHttpResponseAsync(clientStream, "200 Connection Established").ConfigureAwait(false);
                if (ErrorLog.Enabled)
                    ErrorLog.LogConnection($"[Tailscale][Relay] CONNECT {host}:{port} via {effectiveRoute} -> 200 ({connectSw.ElapsedMilliseconds}ms)");

                var upstreamStream = upstream.GetStream();
                var tunnelSw = Stopwatch.StartNew();

                var c2u = PumpClientToUpstreamAsync(clientStream, upstreamStream, effectiveRoute.Kind, upstream, tunnel, stats, tunnel.Token);
                var u2c = CopyStreamSafeAsync(upstreamStream, clientStream, client, tunnel, stats, isUpstreamToClient: true, tunnel.Token);
                await WaitTunnelFinishAsync(c2u, u2c, tunnel, tunnel.Token).ConfigureAwait(false);

                var hadTransportError = !string.IsNullOrEmpty(stats.ErrorUp) || !string.IsNullOrEmpty(stats.ErrorDown);
                var hadZeroResponse = stats.BytesUp > 0 && stats.BytesDown == 0;
                if (ErrorLog.Enabled && (hadZeroResponse || hadTransportError))
                {
                    ErrorLog.LogConnection(
                        $"[Tailscale][Relay] CONNECT {host}:{port} via {effectiveRoute} closed in {tunnelSw.ElapsedMilliseconds}ms " +
                        $"(up={stats.BytesUp}B, down={stats.BytesDown}B, firstChunk={stats.FirstChunkLen}B, aborted={tunnel.IsAborted}" +
                        $"{(string.IsNullOrEmpty(stats.ErrorUp) ? "" : ", errUp=" + stats.ErrorUp)}" +
                        $"{(string.IsNullOrEmpty(stats.ErrorDown) ? "" : ", errDown=" + stats.ErrorDown)})");
                }

                if (!tunnel.IsAborted && !shutdownToken.IsCancellationRequested && IsControlplaneHost(host) && (hadZeroResponse || hadTransportError))
                {
                    var reason = hadZeroResponse
                        ? $"zero_down_after_{stats.BytesUp}B_up"
                        : (!string.IsNullOrEmpty(stats.ErrorDown) ? stats.ErrorDown! : stats.ErrorUp!);
                    RaiseControlplaneFailure(effectiveRoute, host, reason, stats.BytesUp, stats.BytesDown);
                }
            }
            else
            {
                // Standard plain HTTP proxy request (e.g. POST http://controlplane.tailscale.com/ts2021)
                if (!Uri.TryCreate(target, UriKind.Absolute, out var targetUri))
                {
                    await SendSimpleHttpResponseAsync(clientStream, "400 Bad Request").ConfigureAwait(false);
                    return;
                }

                var effectiveRoute = IsLoopbackHost(targetUri.Host) ? TailscaleRoute.Direct : route;
                var tunnel = new ActiveTunnel(client, shutdownToken);
                _activeTunnels[tunnelId] = tunnel;
                if (!IsGenerationCurrent(capturedGen))
                {
                    tunnel.Abort();
                    return;
                }

                var connectSw = Stopwatch.StartNew();
                try
                {
                    using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(tunnel.Token);
                    connectCts.CancelAfter(12000);
                    if (effectiveRoute.Kind == TailscaleRouteKind.HttpProxy)
                    {
                        upstream = await TailscaleNetworkProbe
                            .OpenTunnelStreamAsync(TailscaleRoute.Direct, effectiveRoute.Host, effectiveRoute.Port, connectCts.Token)
                            .ConfigureAwait(false);
                    }
                    else
                    {
                        upstream = await TailscaleNetworkProbe
                            .OpenTunnelStreamAsync(effectiveRoute, targetUri.Host, targetUri.Port, connectCts.Token)
                            .ConfigureAwait(false);
                    }
                    if (tunnel.IsAborted || !IsGenerationCurrent(capturedGen))
                    {
                        tunnel.Abort();
                        return;
                    }
                    tunnel.AttachUpstream(upstream);
                    Interlocked.Exchange(ref _consecutiveConnectFailures, 0);
                }
                catch (OperationCanceledException) when (tunnel.IsAborted || shutdownToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    if (ErrorLog.Enabled)
                        ErrorLog.LogConnection($"[Tailscale][Relay] {method} {targetUri.Host}:{targetUri.Port} via {effectiveRoute} FAILED in {connectSw.ElapsedMilliseconds}ms: {ex.GetType().Name}: {ex.Message}");
                    await SendSimpleHttpResponseAsync(clientStream, "502 Bad Gateway").ConfigureAwait(false);
                    RecordConnectFailure(effectiveRoute, $"{targetUri.Host}:{targetUri.Port} -> {ex.Message}");
                    return;
                }

                var stats = new TunnelStats();

                var outboundHeaders = effectiveRoute.Kind == TailscaleRouteKind.HttpProxy
                    ? headerBlock
                    : RewriteHttpRequestToOriginForm(headerBlock, method, targetUri);
                var outboundBytes = Encoding.ASCII.GetBytes(outboundHeaders);
                var upstreamStream = upstream.GetStream();
                if (TailscaleTlsFragmenter.RequiresDpiTransform(effectiveRoute.Kind))
                {
                    await TailscaleTlsFragmenter.WriteFragmentedAsync(
                        upstreamStream, outboundBytes, 0, outboundBytes.Length, effectiveRoute.Kind, tunnel.Token).ConfigureAwait(false);
                }
                else
                {
                    await upstreamStream.WriteAsync(outboundBytes, 0, outboundBytes.Length).ConfigureAwait(false);
                    await upstreamStream.FlushAsync().ConfigureAwait(false);
                }
                stats.BytesUp += outboundBytes.Length;

                var tunnelSw = Stopwatch.StartNew();
                var c2u = CopyStreamSafeAsync(clientStream, upstreamStream, upstream, tunnel, stats, isUpstreamToClient: false, tunnel.Token);
                var u2c = CopyStreamSafeAsync(upstreamStream, clientStream, client, tunnel, stats, isUpstreamToClient: true, tunnel.Token);
                await WaitTunnelFinishAsync(c2u, u2c, tunnel, tunnel.Token).ConfigureAwait(false);

                if (ErrorLog.Enabled && (stats.BytesDown == 0 || !string.IsNullOrEmpty(stats.ErrorUp) || !string.IsNullOrEmpty(stats.ErrorDown)))
                {
                    ErrorLog.LogConnection(
                        $"[Tailscale][Relay] {method} {targetUri.Host}:{targetUri.Port} via {effectiveRoute} closed in {tunnelSw.ElapsedMilliseconds}ms " +
                        $"(up={stats.BytesUp}B, down={stats.BytesDown}B, aborted={tunnel.IsAborted}" +
                        $"{(string.IsNullOrEmpty(stats.ErrorUp) ? "" : ", errUp=" + stats.ErrorUp)}" +
                        $"{(string.IsNullOrEmpty(stats.ErrorDown) ? "" : ", errDown=" + stats.ErrorDown)})");
                }
            }
        }
        catch { }
        finally
        {
            if (_activeTunnels.TryRemove(tunnelId, out var active))
                active.Dispose();
            try { upstream?.Close(); } catch { }
            try { upstream?.Dispose(); } catch { }
            try { client.Close(); } catch { }
            try { client.Dispose(); } catch { }
        }
    }

    private bool IsGenerationCurrent(long capturedGen)
    {
        lock (_sync) return _routeGeneration == capturedGen;
    }

    private static bool IsControlplaneHost(string host) =>
        string.Equals(host?.Trim(), TailscaleNetworkProbe.ControlplaneHost, StringComparison.OrdinalIgnoreCase);

    private void RaiseControlplaneFailure(TailscaleRoute route, string host, string reason, long bytesUp, long bytesDown)
    {
        if (ErrorLog.Enabled)
            ErrorLog.LogConnection($"[Tailscale][Relay] ControlplaneTunnelFailed route={route}, host={host}, reason={reason}, up={bytesUp}B, down={bytesDown}B");
        try { ControlplaneTunnelFailed?.Invoke(this, new TailscaleControlplaneFailureEventArgs(route, host, reason, bytesUp, bytesDown)); } catch { }
    }

    private void RecordConnectFailure(TailscaleRoute route, string reason)
    {
        var count = Interlocked.Increment(ref _consecutiveConnectFailures);
        // Trigger fast re-probe if external proxy or direct route fails repeatedly.
        if (count >= 2)
        {
            var shouldNotify = false;
            lock (_sync)
            {
                if (DateTime.UtcNow - _lastFailureSignalUtc >= TimeSpan.FromSeconds(5))
                {
                    _lastFailureSignalUtc = DateTime.UtcNow;
                    shouldNotify = true;
                }
            }
            if (shouldNotify)
            {
                if (ErrorLog.Enabled)
                    ErrorLog.LogConnection($"[Tailscale][Relay] RouteFailureDetected (failures={count}): route={route}: {reason}");
                try { RouteFailureDetected?.Invoke(this, $"route={route}: {reason}"); } catch { }
            }
        }
    }

    private static string RewriteHttpRequestToOriginForm(string headerBlock, string method, Uri targetUri)
    {
        var firstLineEnd = headerBlock.IndexOf("\r\n", StringComparison.Ordinal);
        var rest = firstLineEnd >= 0 ? headerBlock.Substring(firstLineEnd + 2) : string.Empty;
        var filteredLines = rest
            .Split(new[] { "\r\n" }, StringSplitOptions.None)
            .Where(line => !line.StartsWith("Proxy-Connection:", StringComparison.OrdinalIgnoreCase));
        return $"{method} {targetUri.PathAndQuery} HTTP/1.1\r\n" + string.Join("\r\n", filteredLines);
    }

    private static async Task WaitTunnelFinishAsync(Task c2u, Task u2c, ActiveTunnel tunnel, CancellationToken shutdownToken)
    {
        var first = await Task.WhenAny(c2u, u2c).ConfigureAwait(false);
        var other = first == c2u ? u2c : c2u;
        try
        {
            if (await Task.WhenAny(other, Task.Delay(5000, shutdownToken)).ConfigureAwait(false) != other)
                tunnel.Abort();
        }
        catch
        {
            tunnel.Abort();
        }
        await Task.WhenAll(c2u, u2c).ConfigureAwait(false);
    }

    private static async Task PumpClientToUpstreamAsync(
        Stream clientStream,
        Stream upstreamStream,
        TailscaleRouteKind routeKind,
        TcpClient destinationClient,
        ActiveTunnel tunnel,
        TunnelStats stats,
        CancellationToken cancellationToken)
    {
        try
        {
            if (TailscaleTlsFragmenter.RequiresDpiTransform(routeKind))
            {
                var firstBytes = await TailscaleTlsFragmenter
                    .ForwardFirstChunkAsync(clientStream, upstreamStream, routeKind, cancellationToken)
                    .ConfigureAwait(false);
                if (firstBytes <= 0)
                {
                    try { destinationClient.Client.Shutdown(SocketShutdown.Send); } catch { }
                    return;
                }
                stats.FirstChunkLen = firstBytes;
                stats.BytesUp += firstBytes;
            }
        }
        catch (Exception ex)
        {
            if (!tunnel.IsAborted && !cancellationToken.IsCancellationRequested)
                stats.ErrorUp = $"{ex.GetType().Name}: {ex.Message}";
            tunnel.Abort();
            return;
        }

        await CopyStreamSafeAsync(clientStream, upstreamStream, destinationClient, tunnel, stats, isUpstreamToClient: false, cancellationToken).ConfigureAwait(false);
    }

    private static async Task CopyStreamSafeAsync(
        Stream source,
        Stream destination,
        TcpClient destinationClient,
        ActiveTunnel tunnel,
        TunnelStats stats,
        bool isUpstreamToClient,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[16384];
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await source.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                if (read <= 0)
                {
                    try { destinationClient.Client.Shutdown(SocketShutdown.Send); } catch { }
                    return;
                }
                await destination.WriteAsync(buffer, 0, read).ConfigureAwait(false);
                await destination.FlushAsync().ConfigureAwait(false);
                if (isUpstreamToClient)
                    stats.BytesDown += read;
                else
                    stats.BytesUp += read;
            }
        }
        catch (Exception ex)
        {
            if (!tunnel.IsAborted && !cancellationToken.IsCancellationRequested)
            {
                var msg = $"{ex.GetType().Name}: {ex.Message}";
                if (isUpstreamToClient) stats.ErrorDown = msg;
                else stats.ErrorUp = msg;
            }
            tunnel.Abort();
        }
    }

    private static async Task SendSimpleHttpResponseAsync(Stream stream, string status)
    {
        try
        {
            var bytes = Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\n\r\n");
            await stream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
        }
        catch { }
    }

    private static bool TryParseHostPort(string target, int defaultPort, out string host, out int port)
    {
        host = string.Empty;
        port = defaultPort;
        if (string.IsNullOrWhiteSpace(target)) return false;

        if (target.StartsWith("[", StringComparison.Ordinal))
        {
            var close = target.IndexOf(']');
            if (close < 0) return false;
            host = target.Substring(1, close - 1);
            if (close + 2 <= target.Length && target[close + 1] == ':')
                return int.TryParse(target.Substring(close + 2), out port) && port > 0 && port <= 65535;
            return true;
        }

        var colon = target.LastIndexOf(':');
        if (colon > 0)
        {
            host = target.Substring(0, colon);
            return int.TryParse(target.Substring(colon + 1), out port) && port > 0 && port <= 65535;
        }

        host = target;
        return true;
    }

    private static bool IsLoopbackHost(string host)
    {
        var h = (host ?? string.Empty).Trim('[', ']').ToLowerInvariant();
        return h == "localhost" || h == "127.0.0.1" || h == "::1" || h.StartsWith("127.", StringComparison.Ordinal);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
            try { _cts?.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }
            _listener = null;
            try { _cts?.Dispose(); } catch { }
            _cts = null;
        }
        AbortActiveTunnels();
    }

    private sealed class TunnelStats
    {
        public long BytesUp;
        public long BytesDown;
        public int FirstChunkLen;
        public string? ErrorUp;
        public string? ErrorDown;
    }

    private sealed class ActiveTunnel : IDisposable
    {
        private readonly TcpClient _client;
        private readonly CancellationTokenSource _cts;
        private TcpClient? _upstream;
        private int _aborted;
        private int _disposed;

        public bool IsAborted => Volatile.Read(ref _aborted) != 0;
        public CancellationToken Token => _cts.Token;

        public ActiveTunnel(TcpClient client, CancellationToken shutdownToken)
        {
            _client = client;
            _cts = CancellationTokenSource.CreateLinkedTokenSource(shutdownToken);
        }

        public void AttachUpstream(TcpClient upstream)
        {
            Interlocked.Exchange(ref _upstream, upstream);
            if (IsAborted)
            {
                try { upstream.Close(); } catch { }
            }
        }

        public void Abort()
        {
            if (Interlocked.Exchange(ref _aborted, 1) != 0) return;
            try { _cts.Cancel(); } catch { }
            try { _client.Close(); } catch { }
            var up = Volatile.Read(ref _upstream);
            if (up != null)
            {
                try { up.Close(); } catch { }
            }
        }

        public void Dispose()
        {
            Abort();
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            try { _cts.Dispose(); } catch { }
        }
    }
}