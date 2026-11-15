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
    /// Inspects UDP and TCP tables for any process bound to <paramref name="port"/> on DNS Pulse loopback candidates or wildcard addresses.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public (string? OccupantName, int? ProcessId) InspectPortConflict(int port, bool excludeSelfProcesses)
    {
        return InspectPortConflict(port, specificAddress: null, excludeSelfProcesses);
    }

    /// <summary>
    /// Inspects UDP and TCP tables for any process bound to <paramref name="port"/> on <paramref name="specificAddress"/>
    /// (or DNS Pulse candidate loopback addresses when <see langword="null"/>) or wildcard addresses.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public (string? OccupantName, int? ProcessId) InspectPortConflict(
        int port,
        IPAddress? specificAddress,
        bool excludeSelfProcesses = true)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        List<(string Name, int Pid, IPAddress Address)> listeners = CollectListeners(port, excludeSelfProcesses);
        foreach ((string name, int pid, IPAddress addr) in listeners)
        {
            if (IsMatchingEndpoint(addr, specificAddress))
            {
                PlatformDiagnosticLog.Write(string.Create(
                    CultureInfo.InvariantCulture,
                    $"Port {port} conflict detected on {addr}: '{name}' (PID {pid})."));
                return (name, pid);
            }
        }

        return (null, null);
    }

    /// <summary>
    /// Inspects whether an external listener blocks ALL DNS Pulse candidate loopback endpoints
    /// (<c>127.0.0.1</c> and <c>127.0.53.1..10</c>) on <paramref name="port"/>.
    /// Listeners bound only to unrelated loopback IPs such as <c>127.0.0.53</c> do not report a blocking conflict
    /// while at least one candidate loopback endpoint remains free.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public (string? OccupantName, int? ProcessId) InspectBlockingPortConflict(int port, bool excludeSelfProcesses = true)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        List<(string Name, int Pid, IPAddress Address)> listeners = CollectListeners(port, excludeSelfProcesses);
        if (listeners.Count == 0)
        {
            return (null, null);
        }

        foreach ((string name, int pid, IPAddress addr) in listeners)
        {
            if (addr.Equals(IPAddress.Any))
            {
                PlatformDiagnosticLog.Write(string.Create(
                    CultureInfo.InvariantCulture,
                    $"Port {port} wildcard conflict detected on {addr}: '{name}' (PID {pid})."));
                return (name, pid);
            }
        }

        HashSet<IPAddress> occupiedAddresses = [.. listeners.Select(static l => l.Address)];
        IReadOnlyList<IPAddress> candidates = LoopbackPortSelector.GetCandidateEndpoints();
        foreach (IPAddress candidate in candidates)
        {
            if (!occupiedAddresses.Contains(candidate))
            {
                return (null, null);
            }
        }

        foreach ((string name, int pid, IPAddress addr) in listeners)
        {
            if (candidates.Contains(addr))
            {
                PlatformDiagnosticLog.Write(string.Create(
                    CultureInfo.InvariantCulture,
                    $"Port {port} conflict blocks all candidate loopbacks (e.g. {addr}): '{name}' (PID {pid})."));
                return (name, pid);
            }
        }

        return (null, null);
    }

    private static List<(string Name, int Pid, IPAddress Address)> CollectListeners(int port, bool excludeSelfProcesses)
    {
        List<(string Name, int Pid, IPAddress Address)> results = [];
        CollectUdpListeners(AfInet, port, excludeSelfProcesses, results);
        CollectUdpListeners(AfInet6, port, excludeSelfProcesses, results);
        CollectTcpListeners(AfInet, port, excludeSelfProcesses, results);
        CollectTcpListeners(AfInet6, port, excludeSelfProcesses, results);
        return results;
    }

    private static void CollectUdpListeners(
        int addressFamily,
        int targetPort,
        bool excludeSelfProcesses,
        List<(string Name, int Pid, IPAddress Address)> results)
    {
        int rowSize = addressFamily == AfInet ? 12 : 28;
        int bufferSize = 0;
        uint probeResult = NativeMethods.GetExtendedUdpTable(0, ref bufferSize, false, addressFamily, UdpTableOwnerPid, 0);
        if (probeResult != ErrorInsufficientBuffer && probeResult != NoError)
        {
            return;
        }

        if (bufferSize <= 4)
        {
            return;
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
                    return;
                }

                int count = Marshal.ReadInt32(buffer, 0);
                if (count <= 0)
                {
                    return;
                }

                int offset = 4;
                for (int i = 0; i < count; i++)
                {
                    if (offset + rowSize > bufferSize)
                    {
                        break;
                    }

                    IPAddress addr;
                    int rawPort;
                    int pid;

                    if (addressFamily == AfInet)
                    {
                        uint rawAddr = unchecked((uint)Marshal.ReadInt32(buffer, offset));
                        rawPort = Marshal.ReadInt32(buffer, offset + 4);
                        pid = Marshal.ReadInt32(buffer, offset + 8);
                        addr = new IPAddress(rawAddr);
                    }
                    else
                    {
                        byte[] addrBytes = new byte[16];
                        Marshal.Copy(buffer + offset, addrBytes, 0, 16);
                        rawPort = Marshal.ReadInt32(buffer, offset + 20);
                        pid = Marshal.ReadInt32(buffer, offset + 24);
                        addr = new IPAddress(addrBytes);
                    }

                    int port = DecodeNetworkPort(rawPort);
                    if (port == targetPort && pid > 0)
                    {
                        string name = ResolveProcessName(pid);
                        if (excludeSelfProcesses && IsSelfProcess(name))
                        {
                            PlatformDiagnosticLog.Write(string.Create(
                                CultureInfo.InvariantCulture,
                                $"Ignoring self-owned UDP listener on {addr}:{targetPort}: '{name}' (PID {pid})."));
                        }
                        else
                        {
                            results.Add((name, pid, addr));
                        }
                    }

                    offset += rowSize;
                }

                return;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static void CollectTcpListeners(
        int addressFamily,
        int targetPort,
        bool excludeSelfProcesses,
        List<(string Name, int Pid, IPAddress Address)> results)
    {
        int rowSize = addressFamily == AfInet ? 24 : 56;
        int bufferSize = 0;
        uint probeResult = NativeMethods.GetExtendedTcpTable(0, ref bufferSize, false, addressFamily, TcpTableOwnerPidListener, 0);
        if (probeResult != ErrorInsufficientBuffer && probeResult != NoError)
        {
            return;
        }

        if (bufferSize <= 4)
        {
            return;
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
                    return;
                }

                int count = Marshal.ReadInt32(buffer, 0);
                if (count <= 0)
                {
                    return;
                }

                int offset = 4;
                for (int i = 0; i < count; i++)
                {
                    if (offset + rowSize > bufferSize)
                    {
                        break;
                    }

                    IPAddress addr;
                    int rawPort;
                    int pid;

                    if (addressFamily == AfInet)
                    {
                        uint rawAddr = unchecked((uint)Marshal.ReadInt32(buffer, offset + 4));
                        rawPort = Marshal.ReadInt32(buffer, offset + 8);
                        pid = Marshal.ReadInt32(buffer, offset + 20);
                        addr = new IPAddress(rawAddr);
                    }
                    else
                    {
                        byte[] addrBytes = new byte[16];
                        Marshal.Copy(buffer + offset, addrBytes, 0, 16);
                        rawPort = Marshal.ReadInt32(buffer, offset + 20);
                        pid = Marshal.ReadInt32(buffer, offset + 52);
                        addr = new IPAddress(addrBytes);
                    }

                    int port = DecodeNetworkPort(rawPort);
                    if (port == targetPort && pid > 0)
                    {
                        string name = ResolveProcessName(pid);
                        if (excludeSelfProcesses && IsSelfProcess(name))
                        {
                            PlatformDiagnosticLog.Write(string.Create(
                                CultureInfo.InvariantCulture,
                                $"Ignoring self-owned TCP listener on {addr}:{targetPort}: '{name}' (PID {pid})."));
                        }
                        else
                        {
                            results.Add((name, pid, addr));
                        }
                    }

                    offset += rowSize;
                }

                return;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static int DecodeNetworkPort(int rawPort)
    {
        return ((rawPort & 0xFF) << 8) | ((rawPort >> 8) & 0xFF);
    }

    private static bool IsMatchingEndpoint(IPAddress listenerAddress, IPAddress? specificTarget)
    {
        if (listenerAddress.Equals(IPAddress.Any) || listenerAddress.Equals(IPAddress.IPv6Any))
        {
            return true;
        }

        if (specificTarget is not null)
        {
            return listenerAddress.Equals(specificTarget);
        }

        if (listenerAddress.Equals(IPAddress.IPv6Loopback))
        {
            return true;
        }

        return LoopbackPortSelector.GetCandidateEndpoints().Contains(listenerAddress);
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
