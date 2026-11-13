using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using DnsPulse.Core.Cryptography;
using DnsPulse.Core.Models;
using DnsPulse.Core.Stamps;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// Validated DNSCrypt v2 resolver certificate parsed from a <c>2.dnscrypt-cert.</c> TXT record.
/// </summary>
public sealed record DnsCryptCertificate
{
    public ushort EsVersion { get; init; }

    public ushort MinorVersion { get; init; }

    public ImmutableArray<byte> ResolverPublicKey { get; init; } = [];

    public ImmutableArray<byte> ClientMagic { get; init; } = [];

    public uint Serial { get; init; }

    public DateTimeOffset ValidFromUtc { get; init; }

    public DateTimeOffset ValidUntilUtc { get; init; }

    public bool IsValidAt(DateTimeOffset timestampUtc)
    {
        return timestampUtc >= ValidFromUtc && timestampUtc <= ValidUntilUtc;
    }
}

/// <summary>
/// Pure-managed DNSCrypt v2 and Anonymized DNSCrypt client supporting XSalsa20-Poly1305 (<c>0x0001</c>)
/// and XChaCha20-Poly1305 (<c>0x0002</c>), Ed25519 certificate verification, and Anonymized DNSCrypt relaying.
/// </summary>
public sealed class DnsCryptClient : IDnsUpstreamClient
{
    private const int DefaultDnsCryptPort = 443;
    private const int MinimumQueryPadding = 256;
    private const int PaddingBlockMultiple = 64;
    private const int ClientNonceLength = 12;
    private const int MinCertificateBytes = 124;

    private static readonly byte[] CertMagic = [(byte)'D', (byte)'N', (byte)'S', (byte)'C'];
    private static readonly byte[] ServerMagic = [0x72, 0x36, 0x66, 0x6E, 0x76, 0x57, 0x6A, 0x38];
    private static readonly byte[] AnonymizedRelayMagic = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00];

    private readonly TransportOptions _options;
    private readonly UdpTcpDnsClient _plainTransport;
    private readonly ConcurrentDictionary<string, DnsCryptCertificate> _certificateCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Initializes a new <see cref="DnsCryptClient"/>.
    /// </summary>
    public DnsCryptClient(
        DnsProtocol protocol = DnsProtocol.DnsCrypt,
        TransportOptions? options = null)
    {
        if (protocol is not DnsProtocol.DnsCrypt and not DnsProtocol.AnonymizedDnsCrypt)
        {
            throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "DnsCryptClient supports only DnsCrypt or AnonymizedDnsCrypt.");
        }

        Protocol = protocol;
        _options = options ?? new TransportOptions();
        _plainTransport = new UdpTcpDnsClient(DnsProtocol.Udp, null, _options);
    }

    /// <inheritdoc />
    public DnsProtocol Protocol { get; }

    /// <summary>
    /// Pre-registers a validated <see cref="DnsCryptCertificate"/> in the client cache for the given key.
    /// </summary>
    public void RegisterCertificate(string cacheKey, DnsCryptCertificate certificate)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheKey);
        ArgumentNullException.ThrowIfNull(certificate);
        _certificateCache[cacheKey] = certificate;
    }

    /// <summary>
    /// Parses and Ed25519-verifies a raw DNSCrypt v2 binary certificate against <paramref name="providerPublicKey"/>.
    /// </summary>
    public static DnsCryptCertificate ParseCertificate(
        ReadOnlySpan<byte> certificateBytes,
        ReadOnlySpan<byte> providerPublicKey,
        DateTimeOffset? currentTimeUtc = null)
    {
        if (certificateBytes.Length < MinCertificateBytes)
        {
            throw new FormatException($"DNSCrypt certificate must be at least {MinCertificateBytes} bytes.");
        }

        if (!certificateBytes[..4].SequenceEqual(CertMagic))
        {
            throw new FormatException("DNSCrypt certificate is missing 'DNSC' magic header.");
        }

        ushort esVersion = BinaryPrimitives.ReadUInt16BigEndian(certificateBytes[4..6]);
        if (esVersion is not 1 and not 2)
        {
            throw new NotSupportedException($"Unsupported DNSCrypt ES version: 0x{esVersion:X4}.");
        }

        ushort minorVersion = BinaryPrimitives.ReadUInt16BigEndian(certificateBytes[6..8]);
        ReadOnlySpan<byte> signature = certificateBytes[8..72];
        ReadOnlySpan<byte> signedBody = certificateBytes[72..];

        if (!Ed25519Verifier.Verify(providerPublicKey, signedBody, signature))
        {
            throw new CryptographicException("DNSCrypt certificate Ed25519 signature verification failed.");
        }

        byte[] resolverPk = certificateBytes[72..104].ToArray();
        byte[] clientMagic = certificateBytes[104..112].ToArray();
        uint serial = BinaryPrimitives.ReadUInt32BigEndian(certificateBytes[112..116]);
        uint tsStart = BinaryPrimitives.ReadUInt32BigEndian(certificateBytes[116..120]);
        uint tsEnd = BinaryPrimitives.ReadUInt32BigEndian(certificateBytes[120..124]);

        DateTimeOffset validFrom = DateTimeOffset.FromUnixTimeSeconds(tsStart);
        DateTimeOffset validUntil = DateTimeOffset.FromUnixTimeSeconds(tsEnd);
        DateTimeOffset now = currentTimeUtc ?? DateTimeOffset.UtcNow;

        DnsCryptCertificate cert = new()
        {
            EsVersion = esVersion,
            MinorVersion = minorVersion,
            ResolverPublicKey = ImmutableArray.Create(resolverPk),
            ClientMagic = ImmutableArray.Create(clientMagic),
            Serial = serial,
            ValidFromUtc = validFrom,
            ValidUntilUtc = validUntil
        };

        if (!cert.IsValidAt(now))
        {
            throw new CryptographicException("DNSCrypt certificate is expired or not yet valid.");
        }

        return cert;
    }

    /// <summary>
    /// Extracts raw binary DNSCrypt certificate bytes from a DNS <c>TXT</c> resource record.
    /// </summary>
    public static byte[] ExtractCertificateBytesFromTxtRecord(DnsResourceRecord txtRecord)
    {
        ArgumentNullException.ThrowIfNull(txtRecord);

        if (!txtRecord.RawData.IsEmpty)
        {
            ReadOnlySpan<byte> raw = txtRecord.RawData.Span;
            using MemoryStream ms = new(raw.Length);
            int offset = 0;
            while (offset < raw.Length)
            {
                int len = raw[offset++];
                if (offset + len > raw.Length)
                {
                    throw new FormatException("Malformed TXT character-string inside DNSCrypt certificate record.");
                }

                ms.Write(raw.Slice(offset, len));
                offset += len;
            }

            return ms.ToArray();
        }

        if (txtRecord.TxtStrings.Count > 0)
        {
            using MemoryStream fallback = new();
            foreach (string s in txtRecord.TxtStrings)
            {
                byte[] chunk = Encoding.Latin1.GetBytes(s);
                fallback.Write(chunk);
            }

            return fallback.ToArray();
        }

        throw new FormatException("TXT record contains no DNSCrypt certificate payload.");
    }

    /// <inheritdoc />
    public async Task<UpstreamQueryResult> QueryAsync(
        DnsMessage query,
        DnsServerEntry upstream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(upstream);

        (DnsStamp targetStamp, IPEndPoint targetEndPoint, IPEndPoint? relayEndPoint) = ResolveEndpoints(upstream);
        string cacheKey = string.Create(CultureInfo.InvariantCulture, $"{targetEndPoint}|{targetStamp.ProviderName}");

        if (!_certificateCache.TryGetValue(cacheKey, out DnsCryptCertificate? certificate)
            || !certificate.IsValidAt(DateTimeOffset.UtcNow))
        {
            certificate = await FetchCertificateAsync(targetStamp, targetEndPoint, cancellationToken).ConfigureAwait(false);
            _certificateCache[cacheKey] = certificate;
        }

        Stopwatch stopwatch = Stopwatch.StartNew();

        ManagedCryptoPrimitives.GenerateX25519KeyPair(out byte[] clientSk, out byte[] clientPk);
        byte[] sharedKey = certificate.EsVersion == 1
            ? ManagedCryptoPrimitives.ComputeXSalsa20SharedKey(clientSk, certificate.ResolverPublicKey.AsSpan())
            : ManagedCryptoPrimitives.ComputeXChaCha20SharedKey(clientSk, certificate.ResolverPublicKey.AsSpan());

        byte[] clientNonce = RandomNumberGenerator.GetBytes(ClientNonceLength);
        byte[] fullQueryNonce = new byte[ManagedCryptoPrimitives.Nonce24Size];
        clientNonce.CopyTo(fullQueryNonce, 0);

        byte[] queryWire = DnsWireCodec.Serialize(query);
        int minPadding = relayEndPoint is not null ? 512 : MinimumQueryPadding;
        byte[] paddedQuery = ManagedCryptoPrimitives.PadIso7816(queryWire, minPadding, PaddingBlockMultiple);

        byte[] encryptedBox = certificate.EsVersion == 1
            ? ManagedCryptoPrimitives.SealXSalsa20Poly1305(sharedKey, fullQueryNonce, paddedQuery)
            : ManagedCryptoPrimitives.SealXChaCha20Poly1305(sharedKey, fullQueryNonce, paddedQuery);

        byte[] dnsCryptPacket = BuildQueryPacket(
            certificate.ClientMagic.AsSpan(),
            clientPk,
            clientNonce,
            encryptedBox);

        IPEndPoint sendDestination = relayEndPoint ?? targetEndPoint;
        byte[] wirePayload = relayEndPoint is not null
            ? WrapAnonymizedRelayPacket(targetEndPoint, dnsCryptPacket)
            : dnsCryptPacket;

        using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_options.Timeout);

        try
        {
            byte[] responseBytes = await SendAndReceivePacketAsync(
                sendDestination,
                wirePayload,
                preferTcp: wirePayload.Length > 1252,
                timeoutCts.Token).ConfigureAwait(false);

            DnsMessage response = DecryptResponsePacket(responseBytes, sharedKey, certificate.EsVersion, clientNonce);
            if (response.Header.Id != query.Header.Id)
            {
                throw new InvalidDataException(
                    $"DNSCrypt response ID mismatch (expected {query.Header.Id}, received {response.Header.Id}).");
            }

            stopwatch.Stop();
            DnsProtocol protocolUsed = relayEndPoint is not null ? DnsProtocol.AnonymizedDnsCrypt : DnsProtocol.DnsCrypt;
            string endpointLabel = relayEndPoint is not null
                ? string.Create(CultureInfo.InvariantCulture, $"{targetEndPoint} via {relayEndPoint}")
                : targetEndPoint.ToString();

            return new UpstreamQueryResult(response, stopwatch.Elapsed, endpointLabel, protocolUsed);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested && timeoutCts.IsCancellationRequested)
        {
            throw new TimeoutException($"DNSCrypt query to {sendDestination} timed out after {_options.Timeout.TotalMilliseconds:F0} ms.", ex);
        }
    }

    /// <summary>
    /// Generates an ephemeral X25519 keypair for DNSCrypt v2 sessions.
    /// </summary>
    public static (byte[] SecretKey, byte[] PublicKey) GenerateX25519KeyPair()
    {
        ManagedCryptoPrimitives.GenerateX25519KeyPair(out byte[] secretKey, out byte[] publicKey);
        return (secretKey, publicKey);
    }

    /// <summary>
    /// Computes an X25519 scalar multiplication (<see cref="ReadOnlySpan{T}"/> of 32 bytes).
    /// </summary>
    public static byte[] X25519ScalarMult(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> uCoordinate)
    {
        return ManagedCryptoPrimitives.X25519ScalarMult(scalar, uCoordinate);
    }

    /// <summary>
    /// Derives the DNSCrypt v2 symmetric shared key for ES version 1 (XSalsa20) or 2 (XChaCha20).
    /// </summary>
    public static byte[] DeriveSharedKey(ushort esVersion, ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> peerPublicKey)
    {
        return esVersion switch
        {
            1 => ManagedCryptoPrimitives.ComputeXSalsa20SharedKey(secretKey, peerPublicKey),
            2 => ManagedCryptoPrimitives.ComputeXChaCha20SharedKey(secretKey, peerPublicKey),
            _ => throw new NotSupportedException($"Unsupported DNSCrypt ES version: 0x{esVersion:X4}.")
        };
    }

    /// <summary>
    /// Encrypts a plaintext payload using DNSCrypt v2 (<c>0x0001</c> XSalsa20-Poly1305 or <c>0x0002</c> XChaCha20-Poly1305).
    /// </summary>
    public static byte[] SealBox(ushort esVersion, ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> plaintext)
    {
        return esVersion switch
        {
            1 => ManagedCryptoPrimitives.SealXSalsa20Poly1305(sharedKey, nonce24, plaintext),
            2 => ManagedCryptoPrimitives.SealXChaCha20Poly1305(sharedKey, nonce24, plaintext),
            _ => throw new NotSupportedException($"Unsupported DNSCrypt ES version: 0x{esVersion:X4}.")
        };
    }

    /// <summary>
    /// Decrypts a DNSCrypt v2 encrypted box (<c>mac[16] || ciphertext</c>).
    /// </summary>
    public static byte[] OpenBox(ushort esVersion, ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> box)
    {
        return esVersion switch
        {
            1 => ManagedCryptoPrimitives.OpenXSalsa20Poly1305(sharedKey, nonce24, box),
            2 => ManagedCryptoPrimitives.OpenXChaCha20Poly1305(sharedKey, nonce24, box),
            _ => throw new NotSupportedException($"Unsupported DNSCrypt ES version: 0x{esVersion:X4}.")
        };
    }

    /// <summary>
    /// Pads a DNS wire payload using ISO/IEC 7816-4 padding.
    /// </summary>
    public static byte[] PadIso7816(ReadOnlySpan<byte> data, int minLength, int blockMultiple)
    {
        return ManagedCryptoPrimitives.PadIso7816(data, minLength, blockMultiple);
    }

    /// <summary>
    /// Removes ISO/IEC 7816-4 padding from a decrypted DNSCrypt payload.
    /// </summary>
    public static byte[] UnpadIso7816(ReadOnlySpan<byte> padded)
    {
        return ManagedCryptoPrimitives.UnpadIso7816(padded).ToArray();
    }

    internal static byte[] BuildQueryPacket(
        ReadOnlySpan<byte> clientMagic,
        ReadOnlySpan<byte> clientPublicKey,
        ReadOnlySpan<byte> clientNonce,
        ReadOnlySpan<byte> encryptedBox)
    {
        byte[] packet = new byte[8 + 32 + ClientNonceLength + encryptedBox.Length];
        clientMagic.CopyTo(packet.AsSpan(0, 8));
        clientPublicKey.CopyTo(packet.AsSpan(8, 32));
        clientNonce.CopyTo(packet.AsSpan(40, ClientNonceLength));
        encryptedBox.CopyTo(packet.AsSpan(52));
        return packet;
    }

    internal static byte[] WrapAnonymizedRelayPacket(IPEndPoint targetEndPoint, ReadOnlySpan<byte> dnsCryptPacket)
    {
        byte[] packet = new byte[10 + 16 + 2 + dnsCryptPacket.Length];
        AnonymizedRelayMagic.CopyTo(packet.AsSpan(0, 10));

        IPAddress mapped = targetEndPoint.Address.AddressFamily == AddressFamily.InterNetwork
            ? targetEndPoint.Address.MapToIPv6()
            : targetEndPoint.Address;

        if (!mapped.TryWriteBytes(packet.AsSpan(10, 16), out int written) || written != 16)
        {
            throw new FormatException("Failed to encode target IP as 16-byte IPv6 address for Anonymized DNSCrypt.");
        }

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(26, 2), (ushort)targetEndPoint.Port);
        dnsCryptPacket.CopyTo(packet.AsSpan(28));
        return packet;
    }

    internal static DnsMessage DecryptResponsePacket(
        ReadOnlySpan<byte> responseBytes,
        ReadOnlySpan<byte> sharedKey,
        ushort esVersion,
        ReadOnlySpan<byte> expectedClientNonce)
    {
        if (responseBytes.Length < 32 + ManagedCryptoPrimitives.TagSize)
        {
            throw new InvalidDataException("DNSCrypt response packet is too short.");
        }

        if (!responseBytes[..8].SequenceEqual(ServerMagic))
        {
            throw new CryptographicException("DNSCrypt response has invalid server magic header.");
        }

        ReadOnlySpan<byte> respClientNonce = responseBytes[8..20];
        if (!CryptographicOperations.FixedTimeEquals(respClientNonce, expectedClientNonce))
        {
            throw new CryptographicException("DNSCrypt response client nonce mismatch.");
        }

        ReadOnlySpan<byte> serverNonce = responseBytes[20..32];
        Span<byte> fullNonce = stackalloc byte[ManagedCryptoPrimitives.Nonce24Size];
        respClientNonce.CopyTo(fullNonce[..12]);
        serverNonce.CopyTo(fullNonce[12..24]);

        ReadOnlySpan<byte> box = responseBytes[32..];
        byte[] paddedPlaintext = esVersion == 1
            ? ManagedCryptoPrimitives.OpenXSalsa20Poly1305(sharedKey, fullNonce, box)
            : ManagedCryptoPrimitives.OpenXChaCha20Poly1305(sharedKey, fullNonce, box);

        ReadOnlySpan<byte> dnsBytes = ManagedCryptoPrimitives.UnpadIso7816(paddedPlaintext);
        return DnsWireCodec.Parse(dnsBytes);
    }

    private async Task<DnsCryptCertificate> FetchCertificateAsync(
        DnsStamp stamp,
        IPEndPoint targetEndPoint,
        CancellationToken cancellationToken)
    {
        string certDomain = stamp.ProviderName.StartsWith("2.dnscrypt-cert.", StringComparison.OrdinalIgnoreCase)
            ? stamp.ProviderName
            : string.Concat("2.dnscrypt-cert.", stamp.ProviderName);

        ushort queryId = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue);
        DnsMessage certQuery = DnsMessage.CreateQuery(queryId, certDomain, DnsRecordType.TXT, enableEdns0: false);

        DnsServerEntry plainTarget = new()
        {
            Id = "dnscrypt-cert-fetch",
            Name = stamp.ProviderName,
            Protocol = DnsProtocol.Udp,
            PrimaryIp = targetEndPoint.Address.ToString(),
            Port = targetEndPoint.Port
        };

        UpstreamQueryResult result = await _plainTransport.QueryAsync(certQuery, plainTarget, cancellationToken).ConfigureAwait(false);
        DnsCryptCertificate? best = null;
        DateTimeOffset now = DateTimeOffset.UtcNow;

        foreach (DnsResourceRecord record in result.Response.Answers)
        {
            if (record.RecordType != DnsRecordType.TXT)
            {
                continue;
            }

            try
            {
                byte[] certBytes = ExtractCertificateBytesFromTxtRecord(record);
                DnsCryptCertificate parsed = ParseCertificate(certBytes, stamp.PublicKey.AsSpan(), now);
                if (best is null || parsed.Serial > best.Serial)
                {
                    best = parsed;
                }
            }
            catch (FormatException)
            {
                // Ignore non-certificate TXT records.
            }
            catch (CryptographicException)
            {
                // Ignore invalid or expired certificate entries while searching for a valid one.
            }
        }

        return best ?? throw new CryptographicException($"No valid DNSCrypt v2 certificate found for '{stamp.ProviderName}'.");
    }

    private static async Task<byte[]> SendAndReceivePacketAsync(
        IPEndPoint destination,
        byte[] payload,
        bool preferTcp,
        CancellationToken cancellationToken)
    {
        if (!preferTcp)
        {
            try
            {
                using Socket udpSocket = new(destination.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                await udpSocket.ConnectAsync(destination, cancellationToken).ConfigureAwait(false);
                await udpSocket.SendAsync(payload.AsMemory(), SocketFlags.None, cancellationToken).ConfigureAwait(false);

                byte[] buffer = new byte[4096];
                int read = await udpSocket.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, cancellationToken).ConfigureAwait(false);
                if (read > 0)
                {
                    return buffer[..read];
                }
            }
            catch (SocketException) when (!cancellationToken.IsCancellationRequested)
            {
                // Fall back to TCP.
            }
        }

        using Socket tcpSocket = new(destination.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true
        };
        await tcpSocket.ConnectAsync(destination, cancellationToken).ConfigureAwait(false);
        await using NetworkStream stream = new(tcpSocket, ownsSocket: false);

        if (payload.Length > ushort.MaxValue)
        {
            throw new InvalidDataException("DNSCrypt packet exceeds maximum 2-byte TCP frame size.");
        }

        byte[] framed = new byte[2 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(0, 2), (ushort)payload.Length);
        payload.CopyTo(framed.AsSpan(2));

        await stream.WriteAsync(framed.AsMemory(), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        byte[] lenBuf = new byte[2];
        await stream.ReadExactlyAsync(lenBuf.AsMemory(), cancellationToken).ConfigureAwait(false);
        int responseLen = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
        byte[] response = new byte[responseLen];
        await stream.ReadExactlyAsync(response.AsMemory(), cancellationToken).ConfigureAwait(false);
        return response;
    }

    private (DnsStamp TargetStamp, IPEndPoint TargetEndPoint, IPEndPoint? RelayEndPoint) ResolveEndpoints(DnsServerEntry upstream)
    {
        if (string.IsNullOrWhiteSpace(upstream.DnsStampUri))
        {
            throw new InvalidOperationException($"DNSCrypt upstream '{upstream.Name}' requires a valid DnsStampUri (sdns://).");
        }

        string[] stampParts = upstream.DnsStampUri.Split([' ', ',', '|', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        DnsStamp targetStamp = DnsStampCodec.Parse(stampParts[0]);
        if (targetStamp.Protocol != DnsStampProtocol.DnsCrypt)
        {
            throw new FormatException($"Expected DNSCrypt target stamp (0x01), found {targetStamp.Protocol}.");
        }

        IPEndPoint targetEndPoint = ParseIpEndPoint(
            !string.IsNullOrWhiteSpace(targetStamp.ServerAddress) ? targetStamp.ServerAddress : upstream.PrimaryIp,
            upstream.Port ?? DefaultDnsCryptPort);

        IPEndPoint? relayEndPoint = null;
        if (stampParts.Length > 1 && DnsStampCodec.TryParse(stampParts[1], out DnsStamp? relayStamp) && relayStamp is not null)
        {
            if (relayStamp.Protocol != DnsStampProtocol.AnonymizedDnsCryptRelay)
            {
                throw new FormatException($"Expected Anonymized DNSCrypt relay stamp (0x81), found {relayStamp.Protocol}.");
            }

            relayEndPoint = ParseIpEndPoint(relayStamp.ServerAddress, DefaultDnsCryptPort);
        }
        else if (upstream.Protocol == DnsProtocol.AnonymizedDnsCrypt || Protocol == DnsProtocol.AnonymizedDnsCrypt)
        {
            string? relaySource = !string.IsNullOrWhiteSpace(upstream.SmartProxyIp)
                ? upstream.SmartProxyIp
                : upstream.SecondaryIp;

            if (!string.IsNullOrWhiteSpace(relaySource))
            {
                if (DnsStampCodec.TryParse(relaySource.Trim(), out DnsStamp? secondaryRelay) && secondaryRelay is not null)
                {
                    relayEndPoint = ParseIpEndPoint(secondaryRelay.ServerAddress, DefaultDnsCryptPort);
                }
                else
                {
                    relayEndPoint = ParseIpEndPoint(relaySource, DefaultDnsCryptPort);
                }
            }
        }

        return (targetStamp, targetEndPoint, relayEndPoint);
    }

    private static IPEndPoint ParseIpEndPoint(string raw, int defaultPort)
    {
        if (!EndpointResolutionHelper.TryParseEndpointIp(raw, out IPAddress address, out int? port))
        {
            throw new FormatException($"Invalid IP endpoint '{raw}' for DNSCrypt.");
        }

        return new IPEndPoint(address, port ?? defaultPort);
    }
}
