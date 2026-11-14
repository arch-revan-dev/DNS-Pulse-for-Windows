using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;

namespace DnsPulse.Platform.Windows.Networking;

/// <summary>
/// Inspects Windows UDP and TCP socket tables via <c>iphlpapi.dll</c> to identify processes occupying port 53 (or another target port).
/// </summary>
public sealed class Port53ConflictInspector
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int UdpTableOwnerPid = 1;
    private const int TcpTableOwnerPidListener = 3;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint NoError = 0;

    private static readonly HashSet<string> SelfProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "DnsPulse",
        "DnsPulse.App",
        "DnsPulse.Service",
        "DnsPulseService"
    };

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="processName"/> belongs to DNS Pulse itself
    /// (desktop app, renamed portable binary, or companion Windows service) and should never be flagged as an external port conflict.
    /// </summary>
    public static bool IsSelfProcessName(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
        {
            return false;
        }

        string trimmed = processName.Trim();
        if (trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[..^4];
        }

        return SelfProcessNames.Contains(trimmed)
            || trimmed.StartsWith("DnsPulse-", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("DnsPulse_", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSelfProcess(string? processName) => IsSelfProcessName(processName);

    /// <summary>
    /// Inspects UDP and TCP tables for any external process bound to port 53 on loopback or wildcard addresses.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public (string? OccupantName, int? ProcessId) InspectPort53Conflict()
    {
        return InspectPortConflict(53, excludeSelfProcesses: true);
    }

    /// <summary>
    /// Inspects UDP and TCP tables for any external process bound to <paramref name="port"/> on loopback or wildcard addresses.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public (string? OccupantName, int? ProcessId) InspectPortConflict(int port)
    {
        return InspectPortConflict(port, excludeSelfProcesses: true);
    }

    /// <summary>
    /// Inspects UDP and TCP tables for any process bound to <paramref name="port"/> on loopback or wildcard addresses.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public (string? OccupantName, int? ProcessId) InspectPortConflict(int port, bool excludeSelfProcesses)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        (string? Name, int Pid)? candidate =
            FindUdpConflict(AfInet, port, excludeSelfProcesses) ??
            FindUdpConflict(AfInet6, port, excludeSelfProcesses) ??
            FindTcpConflict(AfInet, port, excludeSelfProcesses) ??
            FindTcpConflict(AfInet6, port, excludeSelfProcesses);

        if (candidate is { } found)
        {
            PlatformDiagnosticLog.Write(string.Create(
                CultureInfo.InvariantCulture,
                $"Port {port} conflict detected: '{found.Name}' (PID {found.Pid})."));
            return (found.Name, found.Pid);
        }

        return (null, null);
    }

    private static (string Name, int Pid)? FindUdpConflict(int addressFamily, int targetPort, bool excludeSelfProcesses)
    {
        int rowSize = addressFamily == AfInet ? 12 : 28;
        int bufferSize = 0;
        uint probeResult = NativeMethods.GetExtendedUdpTable(0, ref bufferSize, false, addressFamily, UdpTableOwnerPid, 0);
        if (probeResult != ErrorInsufficientBuffer && probeResult != NoError)
        {
            return null;
        }

        if (bufferSize <= 4)
        {
            return null;
        }

        for (int attempt = 0; attempt < 3; attempt++)
        {
            nint buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                uint result = NativeMethods.GetExtendedUdpTable(buffer, ref bufferSize, false, addressFamily, UdpTableOwnerPid, 0);
                if (result == ErrorInsufficientBuffer)
                {
                    continue;
                }

                if (result != NoError)
                {
                    return null;
                }

                int count = Marshal.ReadInt32(buffer, 0);
                if (count <= 0)
                {
                    return null;
                }

                int offset = 4;
                for (int i = 0; i < count; i++)
                {
                    if (offset + rowSize > bufferSize)
                    {
                        break;
                    }

                    bool isMatchingAddress;
                    int rawPort;
                    int pid;

                    if (addressFamily == AfInet)
                    {
                        uint rawAddr = unchecked((uint)Marshal.ReadInt32(buffer, offset));
                        rawPort = Marshal.ReadInt32(buffer, offset + 4);
                        pid = Marshal.ReadInt32(buffer, offset + 8);
                        isMatchingAddress = IsLoopbackOrAnyV4(rawAddr);
                    }
                    else
                    {
                        byte[] addrBytes = new byte[16];
                        Marshal.Copy(buffer + offset, addrBytes, 0, 16);
                        rawPort = Marshal.ReadInt32(buffer, offset + 20);
                        pid = Marshal.ReadInt32(buffer, offset + 24);
                        isMatchingAddress = IsLoopbackOrAnyV6(addrBytes);
                    }

                    int port = DecodeNetworkPort(rawPort);
                    if (port == targetPort && isMatchingAddress && pid > 0)
                    {
                        string name = ResolveProcessName(pid);
                        if (excludeSelfProcesses && IsSelfProcess(name))
                        {
                            PlatformDiagnosticLog.Write(string.Create(
                                CultureInfo.InvariantCulture,
                                $"Ignoring self-owned UDP listener on port {targetPort}: '{name}' (PID {pid})."));
                        }
                        else
                        {
                            return (name, pid);
                        }
                    }

                    offset += rowSize;
                }

                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return null;
    }

    private static (string Name, int Pid)? FindTcpConflict(int addressFamily, int targetPort, bool excludeSelfProcesses)
    {
        int rowSize = addressFamily == AfInet ? 24 : 56;
        int bufferSize = 0;
        uint probeResult = NativeMethods.GetExtendedTcpTable(0, ref bufferSize, false, addressFamily, TcpTableOwnerPidListener, 0);
        if (probeResult != ErrorInsufficientBuffer && probeResult != NoError)
        {
            return null;
        }

        if (bufferSize <= 4)
        {
            return null;
        }

        for (int attempt = 0; attempt < 3; attempt++)
        {
            nint buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                uint result = NativeMethods.GetExtendedTcpTable(buffer, ref bufferSize, false, addressFamily, TcpTableOwnerPidListener, 0);
                if (result == ErrorInsufficientBuffer)
                {
                    continue;
                }

                if (result != NoError)
                {
                    return null;
                }

                int count = Marshal.ReadInt32(buffer, 0);
                if (count <= 0)
                {
                    return null;
                }

                int offset = 4;
                for (int i = 0; i < count; i++)
                {
                    if (offset + rowSize > bufferSize)
                    {
                        break;
                    }

                    bool isMatchingAddress;
                    int rawPort;
                    int pid;

                    if (addressFamily == AfInet)
                    {
                        uint rawAddr = unchecked((uint)Marshal.ReadInt32(buffer, offset + 4));
                        rawPort = Marshal.ReadInt32(buffer, offset + 8);
                        pid = Marshal.ReadInt32(buffer, offset + 20);
                        isMatchingAddress = IsLoopbackOrAnyV4(rawAddr);
                    }
                    else
                    {
                        byte[] addrBytes = new byte[16];
                        Marshal.Copy(buffer + offset, addrBytes, 0, 16);
                        rawPort = Marshal.ReadInt32(buffer, offset + 20);
                        pid = Marshal.ReadInt32(buffer, offset + 52);
                        isMatchingAddress = IsLoopbackOrAnyV6(addrBytes);
                    }

                    int port = DecodeNetworkPort(rawPort);
                    if (port == targetPort && isMatchingAddress && pid > 0)
                    {
                        string name = ResolveProcessName(pid);
                        if (excludeSelfProcesses && IsSelfProcess(name))
                        {
                            PlatformDiagnosticLog.Write(string.Create(
                                CultureInfo.InvariantCulture,
                                $"Ignoring self-owned TCP listener on port {targetPort}: '{name}' (PID {pid})."));
                        }
                        else
                        {
                            return (name, pid);
                        }
                    }

                    offset += rowSize;
                }

                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return null;
    }

    private static int DecodeNetworkPort(int rawPort)
    {
        return ((rawPort & 0xFF) << 8) | ((rawPort >> 8) & 0xFF);
    }

    private static bool IsLoopbackOrAnyV4(uint rawAddr)
    {
        if (rawAddr == 0)
        {
            return true;
        }

        byte firstOctet = (byte)(rawAddr & 0xFF);
        return firstOctet == 127;
    }

    private static bool IsLoopbackOrAnyV6(byte[] addrBytes)
    {
        IPAddress addr = new(addrBytes);
        return addr.Equals(IPAddress.IPv6Any) || IPAddress.IsLoopback(addr);
    }

    private static string ResolveProcessName(int processId)
    {
        try
        {
            using Process process = Process.GetProcessById(processId);
            return process.ProcessName;
        }
        catch (ArgumentException)
        {
            return string.Create(CultureInfo.InvariantCulture, $"pid:{processId}");
        }
        catch (InvalidOperationException)
        {
            return string.Create(CultureInfo.InvariantCulture, $"pid:{processId}");
        }
        catch (Win32Exception)
        {
            return string.Create(CultureInfo.InvariantCulture, $"pid:{processId}");
        }
    }

    [SuppressMessage("Interoperability", "SYSLIB1054:Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time", Justification = "AllowUnsafeBlocks is not enabled in the project.")]
    private static class NativeMethods
    {
        [DllImport("iphlpapi.dll", EntryPoint = "GetExtendedUdpTable", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern uint GetExtendedUdpTable(
            nint pUdpTable,
            ref int pdwSize,
            [MarshalAs(UnmanagedType.Bool)] bool bOrder,
            int ulAf,
            int tableClass,
            uint reserved);

        [DllImport("iphlpapi.dll", EntryPoint = "GetExtendedTcpTable", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern uint GetExtendedTcpTable(
            nint pTcpTable,
            ref int pdwSize,
            [MarshalAs(UnmanagedType.Bool)] bool bOrder,
            int ulAf,
            int tableClass,
            uint reserved);
    }
}
