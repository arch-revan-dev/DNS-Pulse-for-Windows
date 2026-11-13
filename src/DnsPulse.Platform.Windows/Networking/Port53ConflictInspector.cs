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

    /// <summary>
    /// Inspects UDP and TCP tables for any process bound to port 53 on loopback or wildcard addresses.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public (string? OccupantName, int? ProcessId) InspectPort53Conflict()
    {
        return InspectPortConflict(53);
    }

    /// <summary>
    /// Inspects UDP and TCP tables for any process bound to <paramref name="port"/> on loopback or wildcard addresses.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public (string? OccupantName, int? ProcessId) InspectPortConflict(int port)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        int? udpV4Pid = FindUdpConflictPid(AfInet, port);
        if (udpV4Pid is int pid1)
        {
            return (ResolveProcessName(pid1), pid1);
        }

        int? udpV6Pid = FindUdpConflictPid(AfInet6, port);
        if (udpV6Pid is int pid2)
        {
            return (ResolveProcessName(pid2), pid2);
        }

        int? tcpV4Pid = FindTcpConflictPid(AfInet, port);
        if (tcpV4Pid is int pid3)
        {
            return (ResolveProcessName(pid3), pid3);
        }

        int? tcpV6Pid = FindTcpConflictPid(AfInet6, port);
        if (tcpV6Pid is int pid4)
        {
            return (ResolveProcessName(pid4), pid4);
        }

        return (null, null);
    }

    private static int? FindUdpConflictPid(int addressFamily, int targetPort)
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
                        return pid;
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

    private static int? FindTcpConflictPid(int addressFamily, int targetPort)
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
                        return pid;
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
