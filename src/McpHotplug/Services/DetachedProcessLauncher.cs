using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace McpHotplug.Services;

/// <summary>
/// Launches a standalone Windows executable with bInheritHandles = false so that
/// listening sockets (such as 127.0.0.1:18006) and other kernel handles owned by
/// the current process can never leak across updater/relaunch handoffs.
/// </summary>
internal static class DetachedProcessLauncher
{
    private const uint CreateNoWindow = 0x08000000;
    private const int StartfUseShowWindow = 0x00000001;
    private const short SwHide = 0;

    public static void Start(
        string executablePath,
        IEnumerable<string> arguments,
        string? workingDirectory,
        bool hideWindow)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
            throw new ArgumentException("Executable path must not be empty.", nameof(executablePath));

        var commandLine = new StringBuilder();
        commandLine.Append(QuoteArgument(executablePath));
        foreach (var argument in arguments ?? Enumerable.Empty<string>())
        {
            commandLine.Append(' ');
            commandLine.Append(QuoteArgument(argument ?? string.Empty));
        }

        var startupInfo = new StartupInfo
        {
            cb = Marshal.SizeOf(typeof(StartupInfo))
        };
        if (hideWindow)
        {
            startupInfo.dwFlags = StartfUseShowWindow;
            startupInfo.wShowWindow = SwHide;
        }

        var creationFlags = hideWindow ? CreateNoWindow : 0u;
        var currentDirectory = string.IsNullOrWhiteSpace(workingDirectory) ? null : workingDirectory;

        if (!CreateProcess(
                executablePath,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                creationFlags,
                IntPtr.Zero,
                currentDirectory,
                ref startupInfo,
                out var processInfo))
        {
            var error = Marshal.GetLastWin32Error();
            throw new Win32Exception(error, "CreateProcess failed for " + executablePath + " (Win32=" + error + ").");
        }

        if (processInfo.hThread != IntPtr.Zero)
            CloseHandle(processInfo.hThread);
        if (processInfo.hProcess != IntPtr.Zero)
            CloseHandle(processInfo.hProcess);
    }

    public static string QuoteArgument(string value)
    {
        var result = new StringBuilder();
        result.Append('"');
        var backslashes = 0;

        foreach (var character in value)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }

            if (character == '"')
            {
                result.Append('\\', backslashes * 2 + 1);
                result.Append('"');
                backslashes = 0;
                continue;
            }

            result.Append('\\', backslashes);
            backslashes = 0;
            result.Append(character);
        }

        result.Append('\\', backslashes * 2);
        result.Append('"');
        return result.ToString();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(
        string? lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref StartupInfo lpStartupInfo,
        out ProcessInformation lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);
}
