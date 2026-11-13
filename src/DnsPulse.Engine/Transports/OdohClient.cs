using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DnsPulse.Core.Models;
using DnsPulse.Core.Stamps;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// Parsed RFC 9230 <c>ObliviousDoHConfig</c> entry.
/// </summary>
public sealed record OdohTargetConfig
{
    public ushort Version { get; init; }

    public ushort KemId { get; init; }

    public ushort KdfId { get; init; }

    public ushort AeadId { get; init; }

    public ImmutableArray<byte> PublicKey { get; init; } = [];

    public ImmutableArray<byte> KeyId { get; init; } = [];
}

/// <summary>
/// RFC 9230 Oblivious DNS-over-HTTPS (ODoH) client implementing pure-managed
/// <c>ObliviousDoHConfigs</c> fetching, HPKE Base <c>DHKEM(X25519, HKDF-SHA256)</c> + <c>HKDF-SHA256</c> +
/// <c>AesGcm</c> query encryption and response decryption, and optional ODoH relay forwarding.
/// </summary>
public sealed class OdohClient : IDnsUpstreamClient, IDisposable
{
    private const ushort OdohVersion1 = 0x0001;
    private const string OdohMessageMediaType = "application/oblivious-dns-message";
    private const string OdohConfigsMediaType = "application/oblivious-dns-configs";

    private static readonly byte[] OdohQueryInfo = Encoding.ASCII.GetBytes("odoh query");
    private static readonly byte[] OdohKeyIdLabel = Encoding.ASCII.GetBytes("odoh key id");
    private static readonly byte[] OdohResponseLabel = Encoding.ASCII.GetBytes("odoh response");
    private static readonly byte[] OdohKeyLabel = Encoding.ASCII.GetBytes("odoh key");
    private static readonly byte[] OdohNonceLabel = Encoding.ASCII.GetBytes("odoh nonce");

    private readonly IBootstrapResolver? _bootstrapResolver;
    private readonly TransportOptions _options;
    private readonly ConcurrentDictionary<string, OdohTargetConfig> _configCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, HttpMessageInvoker> _invokers = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="OdohClient"/>.
    /// </summary>
    public OdohClient(
        IBootstrapResolver? bootstrapResolver = null,
        TransportOptions? options = null)
    {
        _bootstrapResolver = bootstrapResolver;
        _options = options ?? new TransportOptions();
    }

    /// <inheritdoc />
    public DnsProtocol Protocol => DnsProtocol.ODoH;

    /// <summary>
    /// Pre-registers a parsed <see cref="OdohTargetConfig"/> for the given target authority (e.g., <c>odoh.example:443</c>).
    /// </summary>
    public void RegisterTargetConfig(string targetAuthority, OdohTargetConfig config)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetAuthority);
        ArgumentNullException.ThrowIfNull(config);
        _configCache[targetAuthority] = config;
    }

    /// <summary>
    /// Parses an RFC 9230 <c>ObliviousDoHConfigs</c> binary blob and returns supported configurations.
    /// </summary>
    public static IReadOnlyList<OdohTargetConfig> ParseConfigs(ReadOnlySpan<byte> configsBlob)
    {
        if (configsBlob.Length < 2)
        {
            throw new FormatException("ObliviousDoHConfigs payload is too short.");
        }

        ushort totalLength = BinaryPrimitives.ReadUInt16BigEndian(configsBlob[..2]);
        if (2 + totalLength > configsBlob.Length)
        {
            throw new FormatException("ObliviousDoHConfigs length exceeds available bytes.");
        }

        List<OdohTargetConfig> list = [];
        int offset = 2;
        int end = 2 + totalLength;

        while (offset < end)
        {
            if (offset + 4 > end)
            {
                throw new FormatException("Truncated ObliviousDoHConfig header.");
            }

            ushort version = BinaryPrimitives.ReadUInt16BigEndian(configsBlob.Slice(offset, 2));
            ushort configLen = BinaryPrimitives.ReadUInt16BigEndian(configsBlob.Slice(offset + 2, 2));
            offset += 4;

            if (offset + configLen > end)
            {
                throw new FormatException("Truncated ObliviousDoHConfig contents.");
            }

            ReadOnlySpan<byte> contents = configsBlob.Slice(offset, configLen);
            offset += configLen;

            if (version != OdohVersion1 || contents.Length < 8)
            {
                continue;
            }

            ushort kemId = BinaryPrimitives.ReadUInt16BigEndian(contents[0..2]);
            ushort kdfId = BinaryPrimitives.ReadUInt16BigEndian(contents[2..4]);
            ushort aeadId = BinaryPrimitives.ReadUInt16BigEndian(contents[4..6]);
            ushort pkLen = BinaryPrimitives.ReadUInt16BigEndian(contents[6..8]);

            if (8 + pkLen != contents.Length)
            {
                throw new FormatException("ObliviousDoHConfig public key length mismatch.");
            }

            if (kemId == ManagedCryptoPrimitives.HpkeKemX25519Sha256
                && kdfId == ManagedCryptoPrimitives.HpkeKdfHkdfSha256
                && aeadId is ManagedCryptoPrimitives.HpkeAeadAes128Gcm or ManagedCryptoPrimitives.HpkeAeadAes256Gcm
                && pkLen == ManagedCryptoPrimitives.KeySize)
            {
                byte[] keyId = ComputeKeyId(contents);
                list.Add(new OdohTargetConfig
                {
                    Version = version,
                    KemId = kemId,
                    KdfId = kdfId,
                    AeadId = aeadId,
                    PublicKey = ImmutableArray.Create(contents[8..].ToArray()),
                    KeyId = ImmutableArray.Create(keyId)
                });
            }
        }

        return list;
    }

    /// <summary>
    /// Serializes a single <see cref="OdohTargetConfig"/> into an RFC 9230 <c>ObliviousDoHConfigs</c> blob.
    /// </summary>
    public static byte[] SerializeConfigs(OdohTargetConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        int contentsLen = 8 + config.PublicKey.Length;
        int configLen = 4 + contentsLen;
        byte[] buffer = new byte[2 + configLen];

        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0, 2), (ushort)configLen);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2, 2), config.Version);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4, 2), (ushort)contentsLen);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(6, 2), config.KemId);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(8, 2), config.KdfId);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(10, 2), config.AeadId);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(12, 2), (ushort)config.PublicKey.Length);
        config.PublicKey.AsSpan().CopyTo(buffer.AsSpan(14));
        return buffer;
    }

    /// <summary>
    /// Computes the RFC 9230 <c>key_id</c> for serialized <c>ObliviousDoHConfigContents</c>.
    /// </summary>
    public static byte[] ComputeKeyId(ReadOnlySpan<byte> configContents)
    {
        Span<byte> prk = stackalloc byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, configContents, ReadOnlySpan<byte>.Empty, prk);
        byte[] keyId = new byte[32];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, keyId, OdohKeyIdLabel);
        return keyId;
    }

    /// <inheritdoc />
    public async Task<UpstreamQueryResult> QueryAsync(
        DnsMessage query,
        DnsServerEntry upstream,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(upstream);

        (Uri targetUri, Uri? relayUri) = ResolveTargetAndRelayUris(upstream);

        using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_options.Timeout);
        CancellationToken effectiveToken = timeoutCts.Token;

        try
        {
            OdohTargetConfig config = await GetOrFetchTargetConfigAsync(upstream, targetUri, effectiveToken).ConfigureAwait(false);
            Stopwatch stopwatch = Stopwatch.StartNew();

            byte[] dnsWire = DnsWireCodec.Serialize(query);
            (byte[] queryBody, byte[] plainQueryStruct, ManagedCryptoPrimitives.HpkeBaseContext hpkeContext) =
                EncryptQueryMessage(dnsWire, config);

            Uri postUri = relayUri is not null
                ? BuildRelayPostUri(relayUri, targetUri)
                : targetUri;

            HttpMessageInvoker invoker = await GetOrCreateInvokerAsync(
                upstream,
                targetUri,
                postUri,
                effectiveToken).ConfigureAwait(false);

            using HttpRequestMessage request = new(HttpMethod.Post, postUri)
            {
                Content = new ByteArrayContent(queryBody),
                Version = HttpVersion.Version20,
                VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(OdohMessageMediaType);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OdohMessageMediaType));

            using HttpResponseMessage response = await invoker.SendAsync(request, effectiveToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            byte[] responseBody = await response.Content.ReadAsByteArrayAsync(effectiveToken).ConfigureAwait(false);
            byte[] responseDnsWire = DecryptResponseMessage(responseBody, plainQueryStruct, hpkeContext);

            DnsMessage parsed = DnsWireCodec.Parse(responseDnsWire);
            if (parsed.Header.Id != query.Header.Id)
            {
                throw new InvalidDataException(
                    $"ODoH response ID mismatch (expected {query.Header.Id}, received {parsed.Header.Id}).");
            }

            stopwatch.Stop();
            string endpointLabel = relayUri is not null
                ? string.Create(CultureInfo.InvariantCulture, $"{targetUri} via {relayUri}")
                : targetUri.ToString();

            return new UpstreamQueryResult(parsed, stopwatch.Elapsed, endpointLabel, DnsProtocol.ODoH);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested && timeoutCts.IsCancellationRequested)
        {
            throw new TimeoutException($"ODoH query to {targetUri} timed out after {_options.Timeout.TotalMilliseconds:F0} ms.", ex);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (KeyValuePair<string, HttpMessageInvoker> pair in _invokers)
        {
            pair.Value.Dispose();
        }

        _invokers.Clear();
    }

    /// <summary>
    /// Encrypts a raw DNS wire query using RFC 9230 HPKE Base mode and returns the wire message and session state.
    /// </summary>
    public static (byte[] WireQuery, byte[] PlainQueryStruct, byte[] HpkeExporterSecret, ushort AeadId) SealQueryForTesting(
        ReadOnlySpan<byte> dnsWireQuery,
        OdohTargetConfig config,
        int paddingLength = 0)
    {
        ArgumentNullException.ThrowIfNull(config);

        (byte[] wireMessage, byte[] plainStruct, ManagedCryptoPrimitives.HpkeBaseContext context) =
            EncryptQueryMessage(dnsWireQuery, config, paddingLength);
        byte[] exportSecret = context.Export(OdohResponseLabel, context.KeyLength);
        return (wireMessage, plainStruct, exportSecret, context.AeadId);
    }

    /// <summary>
    /// Server-side RFC 9230 helper that decrypts an incoming ODoH query and encrypts a DNS wire response.
    /// </summary>
    public static (byte[] DecryptedDnsQuery, byte[] PlainQueryStruct) ProcessQueryAsTarget(
        ReadOnlySpan<byte> wireQuery,
        ReadOnlySpan<byte> targetSecretKey,
        OdohTargetConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        (byte msgType, byte[] keyId, byte[] encryptedPayload) = ParseObliviousMessage(wireQuery);
        if (msgType != 0x01)
        {
            throw new InvalidDataException($"Expected ODoH query message type 0x01, got 0x{msgType:X2}.");
        }

        if (encryptedPayload.Length < ManagedCryptoPrimitives.KeySize)
        {
            throw new FormatException("ODoH encrypted query missing encapsulated X25519 key.");
        }

        ReadOnlySpan<byte> enc = encryptedPayload.AsSpan(0, ManagedCryptoPrimitives.KeySize);
        ReadOnlySpan<byte> ct = encryptedPayload.AsSpan(ManagedCryptoPrimitives.KeySize);
        ManagedCryptoPrimitives.HpkeBaseContext receiverCtx = ManagedCryptoPrimitives.SetupHpkeBaseReceiver(
            enc,
            targetSecretKey,
            config.AeadId,
            OdohQueryInfo);

        byte[] queryAad = BuildMessageHeader(0x01, keyId);
        byte[] plainQueryStruct = receiverCtx.Open(queryAad, ct);
        byte[] dnsQuery = ExtractDnsMessageFromPlaintextStruct(plainQueryStruct);
        return (dnsQuery, plainQueryStruct);
    }

    /// <summary>
    /// Server-side RFC 9230 helper that seals a DNS wire response using the target's HPKE receiver context.
    /// </summary>
    public static byte[] SealResponseAsTarget(
        ReadOnlySpan<byte> wireQuery,
        ReadOnlySpan<byte> targetSecretKey,
        OdohTargetConfig config,
        ReadOnlySpan<byte> dnsWireResponse)
    {
        ArgumentNullException.ThrowIfNull(config);

        (byte _, byte[] keyId, byte[] encryptedPayload) = ParseObliviousMessage(wireQuery);
        ReadOnlySpan<byte> enc = encryptedPayload.AsSpan(0, ManagedCryptoPrimitives.KeySize);
        ReadOnlySpan<byte> ct = encryptedPayload.AsSpan(ManagedCryptoPrimitives.KeySize);
        ManagedCryptoPrimitives.HpkeBaseContext receiverCtx = ManagedCryptoPrimitives.SetupHpkeBaseReceiver(
            enc,
            targetSecretKey,
            config.AeadId,
            OdohQueryInfo);

        byte[] queryAad = BuildMessageHeader(0x01, keyId);
        byte[] plainQueryStruct = receiverCtx.Open(queryAad, ct);

        int nk = receiverCtx.KeyLength;
        int nn = receiverCtx.NonceLength;
        byte[] respNonce = RandomNumberGenerator.GetBytes(nk);
        byte[] secret = receiverCtx.Export(OdohResponseLabel, nk);

        byte[] salt = new byte[plainQueryStruct.Length + 2 + respNonce.Length];
        plainQueryStruct.CopyTo(salt.AsSpan(0));
        BinaryPrimitives.WriteUInt16BigEndian(salt.AsSpan(plainQueryStruct.Length, 2), (ushort)respNonce.Length);
        respNonce.CopyTo(salt.AsSpan(plainQueryStruct.Length + 2));

        byte[] prk = HKDF.Extract(HashAlgorithmName.SHA256, secret, salt);
        byte[] aeadKey = HKDF.Expand(HashAlgorithmName.SHA256, prk, nk, OdohKeyLabel);
        byte[] aeadNonce = HKDF.Expand(HashAlgorithmName.SHA256, prk, nn, OdohNonceLabel);

        byte[] plainRespStruct = BuildPlaintextStruct(dnsWireResponse, paddingLength: 0);
        byte[] respAad = BuildMessageHeader(0x02, respNonce);
        byte[] sealedResp = new byte[plainRespStruct.Length + ManagedCryptoPrimitives.TagSize];

        using AesGcm aes = new(aeadKey, ManagedCryptoPrimitives.TagSize);
        aes.Encrypt(
            aeadNonce,
            plainRespStruct,
            sealedResp.AsSpan(0, plainRespStruct.Length),
            sealedResp.AsSpan(plainRespStruct.Length, ManagedCryptoPrimitives.TagSize),
            respAad);

        return BuildObliviousMessage(0x02, respNonce, sealedResp);
    }

    internal static (byte[] WireMessage, byte[] PlainQueryStruct, ManagedCryptoPrimitives.HpkeBaseContext Context) EncryptQueryMessage(
        ReadOnlySpan<byte> dnsWireQuery,
        OdohTargetConfig config,
        int paddingLength = 0)
    {
        byte[] plainStruct = BuildPlaintextStruct(dnsWireQuery, paddingLength);
        (byte[] enc, ManagedCryptoPrimitives.HpkeBaseContext context) = ManagedCryptoPrimitives.SetupHpkeBaseSender(
            config.PublicKey.AsSpan(),
            config.AeadId,
            OdohQueryInfo);

        byte[] keyId = config.KeyId.IsDefaultOrEmpty ? [] : config.KeyId.AsSpan().ToArray();
        byte[] aad = BuildMessageHeader(0x01, keyId);
        byte[] ct = context.Seal(aad, plainStruct);

        byte[] encryptedPayload = new byte[enc.Length + ct.Length];
        enc.CopyTo(encryptedPayload.AsSpan(0));
        ct.CopyTo(encryptedPayload.AsSpan(enc.Length));

        byte[] wireMessage = BuildObliviousMessage(0x01, keyId, encryptedPayload);
        return (wireMessage, plainStruct, context);
    }

    internal static byte[] DecryptResponseMessage(
        ReadOnlySpan<byte> wireResponse,
        ReadOnlySpan<byte> plainQueryStruct,
        ManagedCryptoPrimitives.HpkeBaseContext hpkeContext)
    {
        (byte msgType, byte[] respNonce, byte[] encryptedMessage) = ParseObliviousMessage(wireResponse);
        if (msgType != 0x02)
        {
            throw new InvalidDataException($"Expected ODoH response message type 0x02, received 0x{msgType:X2}.");
        }

        int nk = hpkeContext.KeyLength;
        int nn = hpkeContext.NonceLength;
        byte[] secret = hpkeContext.Export(OdohResponseLabel, nk);

        byte[] salt = new byte[plainQueryStruct.Length + 2 + respNonce.Length];
        plainQueryStruct.CopyTo(salt.AsSpan(0));
        BinaryPrimitives.WriteUInt16BigEndian(salt.AsSpan(plainQueryStruct.Length, 2), (ushort)respNonce.Length);
        respNonce.CopyTo(salt.AsSpan(plainQueryStruct.Length + 2));

        byte[] prk = HKDF.Extract(HashAlgorithmName.SHA256, secret, salt);
        byte[] aeadKey = HKDF.Expand(HashAlgorithmName.SHA256, prk, nk, OdohKeyLabel);
        byte[] aeadNonce = HKDF.Expand(HashAlgorithmName.SHA256, prk, nn, OdohNonceLabel);

        if (encryptedMessage.Length < ManagedCryptoPrimitives.TagSize)
        {
            throw new CryptographicException("ODoH encrypted response is shorter than 16-byte AEAD tag.");
        }

        byte[] aad = BuildMessageHeader(0x02, respNonce);
        int ptLen = encryptedMessage.Length - ManagedCryptoPrimitives.TagSize;
        byte[] plainStruct = new byte[ptLen];

        using AesGcm aes = new(aeadKey, ManagedCryptoPrimitives.TagSize);
        aes.Decrypt(
            aeadNonce,
            encryptedMessage.AsSpan(0, ptLen),
            encryptedMessage.AsSpan(ptLen, ManagedCryptoPrimitives.TagSize),
            plainStruct,
            aad);

        return ExtractDnsMessageFromPlaintextStruct(plainStruct);
    }

    internal static byte[] BuildPlaintextStruct(ReadOnlySpan<byte> dnsMessage, int paddingLength)
    {
        byte[] buffer = new byte[2 + dnsMessage.Length + 2 + paddingLength];
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0, 2), (ushort)dnsMessage.Length);
        dnsMessage.CopyTo(buffer.AsSpan(2));
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2 + dnsMessage.Length, 2), (ushort)paddingLength);
        return buffer;
    }

    internal static byte[] ExtractDnsMessageFromPlaintextStruct(ReadOnlySpan<byte> plainStruct)
    {
        if (plainStruct.Length < 4)
        {
            throw new FormatException("ODoH plaintext structure is too short.");
        }

        ushort dnsLen = BinaryPrimitives.ReadUInt16BigEndian(plainStruct[..2]);
        if (2 + dnsLen + 2 > plainStruct.Length)
        {
            throw new FormatException("ODoH plaintext DNS message length exceeds payload.");
        }

        ushort paddingLen = BinaryPrimitives.ReadUInt16BigEndian(plainStruct.Slice(2 + dnsLen, 2));
        if (2 + dnsLen + 2 + paddingLen != plainStruct.Length)
        {
            throw new FormatException("ODoH plaintext padding length mismatch.");
        }

        return plainStruct.Slice(2, dnsLen).ToArray();
    }

    internal static byte[] BuildObliviousMessage(byte messageType, ReadOnlySpan<byte> keyIdOrNonce, ReadOnlySpan<byte> encryptedPayload)
    {
        byte[] buffer = new byte[1 + 2 + keyIdOrNonce.Length + 2 + encryptedPayload.Length];
        buffer[0] = messageType;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(1, 2), (ushort)keyIdOrNonce.Length);
        keyIdOrNonce.CopyTo(buffer.AsSpan(3));
        int encLenOffset = 3 + keyIdOrNonce.Length;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(encLenOffset, 2), (ushort)encryptedPayload.Length);
        encryptedPayload.CopyTo(buffer.AsSpan(encLenOffset + 2));
        return buffer;
    }

    internal static (byte MessageType, byte[] KeyIdOrNonce, byte[] EncryptedPayload) ParseObliviousMessage(ReadOnlySpan<byte> wireMessage)
    {
        if (wireMessage.Length < 5)
        {
            throw new FormatException("ObliviousDoHMessage is too short.");
        }

        byte msgType = wireMessage[0];
        ushort keyIdLen = BinaryPrimitives.ReadUInt16BigEndian(wireMessage[1..3]);
        if (3 + keyIdLen + 2 > wireMessage.Length)
        {
            throw new FormatException("ObliviousDoHMessage key_id/nonce exceeds packet length.");
        }

        byte[] keyIdOrNonce = wireMessage.Slice(3, keyIdLen).ToArray();
        int encLenOffset = 3 + keyIdLen;
        ushort encLen = BinaryPrimitives.ReadUInt16BigEndian(wireMessage.Slice(encLenOffset, 2));
        if (encLenOffset + 2 + encLen != wireMessage.Length)
        {
            throw new FormatException("ObliviousDoHMessage encrypted payload length mismatch.");
        }

        byte[] encryptedPayload = wireMessage.Slice(encLenOffset + 2, encLen).ToArray();
        return (msgType, keyIdOrNonce, encryptedPayload);
    }

    private static byte[] BuildMessageHeader(byte messageType, ReadOnlySpan<byte> keyIdOrNonce)
    {
        byte[] aad = new byte[1 + 2 + keyIdOrNonce.Length];
        aad[0] = messageType;
        BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(1, 2), (ushort)keyIdOrNonce.Length);
        keyIdOrNonce.CopyTo(aad.AsSpan(3));
        return aad;
    }

    private async Task<OdohTargetConfig> GetOrFetchTargetConfigAsync(
        DnsServerEntry upstream,
        Uri targetUri,
        CancellationToken cancellationToken)
    {
        if (_configCache.TryGetValue(targetUri.Authority, out OdohTargetConfig? cached))
        {
            return cached;
        }

        Uri configsUri = new UriBuilder(targetUri)
        {
            Path = "/.well-known/odohconfigs",
            Query = string.Empty
        }.Uri;

        HttpMessageInvoker invoker = await GetOrCreateInvokerAsync(upstream, targetUri, configsUri, cancellationToken).ConfigureAwait(false);
        using HttpRequestMessage request = new(HttpMethod.Get, configsUri)
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OdohConfigsMediaType));

        using HttpResponseMessage response = await invoker.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        byte[] blob = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        IReadOnlyList<OdohTargetConfig> configs = ParseConfigs(blob);
        if (configs.Count == 0)
        {
            throw new FormatException($"No supported RFC 9230 ODoH config returned by {configsUri}.");
        }

        _configCache[targetUri.Authority] = configs[0];
        return configs[0];
    }

    private async Task<HttpMessageInvoker> GetOrCreateInvokerAsync(
        DnsServerEntry upstream,
        Uri targetUri,
        Uri endpointUri,
        CancellationToken cancellationToken)
    {
        bool isSameHostAsTarget = string.Equals(endpointUri.DnsSafeHost, targetUri.DnsSafeHost, StringComparison.OrdinalIgnoreCase);
        IReadOnlyList<IPAddress> bootstrapIps = [];
        if (!IPAddress.TryParse(endpointUri.DnsSafeHost, out _))
        {
            if (isSameHostAsTarget)
            {
                bootstrapIps = await EndpointResolutionHelper
                    .ResolveTargetAddressesAsync(upstream, endpointUri.DnsSafeHost, _bootstrapResolver, cancellationToken)
                    .ConfigureAwait(false);
            }
            else if (_bootstrapResolver is not null)
            {
                bootstrapIps = await _bootstrapResolver
                    .ResolveHostAsync(endpointUri.DnsSafeHost, cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        string? spkiPin = isSameHostAsTarget ? upstream.SpkiPinSha256 : null;
        bool useFrag = _options.EnableTlsFragmentation
            || EndpointResolutionHelper.HasTlsFragmentationTag(upstream);
        string cacheKey = string.Create(
            CultureInfo.InvariantCulture,
            $"{endpointUri.Authority}|{string.Join(',', bootstrapIps)}|{spkiPin}|{useFrag}");

        return _invokers.GetOrAdd(cacheKey, _ => CreateInvoker(bootstrapIps, spkiPin, useFrag));
    }

    private HttpMessageInvoker CreateInvoker(
        IReadOnlyList<IPAddress> bootstrapIps,
        string? spkiPinSha256,
        bool useTlsFragmentation)
    {
        string? expectedPin = string.IsNullOrWhiteSpace(spkiPinSha256) ? null : spkiPinSha256;
        X509ChainPolicy? chainPolicy = TlsCertificateValidator.BuildCustomChainPolicy(_options.CustomTrustAnchors);

        SocketsHttpHandler? handler = new()
        {
            PooledConnectionIdleTimeout = _options.ConnectionIdleTimeout,
            AllowAutoRedirect = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = _options.EnabledSslProtocols,
                CertificateChainPolicy = chainPolicy,
                RemoteCertificateValidationCallback = (_, certificate, _, sslPolicyErrors) =>
                    TlsCertificateValidator.ValidateServerCertificate(certificate, sslPolicyErrors, expectedPin)
            }
        };

        try
        {
            if (bootstrapIps.Count > 0 || useTlsFragmentation)
            {
                int chunkSize = _options.TlsFragmentChunkSize;
                TimeSpan? delay = _options.TlsFragmentInterChunkDelay;

                handler.ConnectCallback = async (context, ct) =>
                {
                    IReadOnlyList<IPAddress> targets = bootstrapIps.Count > 0
                        ? bootstrapIps
                        : await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, ct).ConfigureAwait(false);

                    foreach (IPAddress ip in targets)
                    {
                        Socket socket = new(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                        {
                            NoDelay = true
                        };
                        bool transferred = false;
                        try
                        {
                            await socket.ConnectAsync(new IPEndPoint(ip, context.DnsEndPoint.Port), ct).ConfigureAwait(false);
                            Stream stream = useTlsFragmentation
                                ? new TlsFragmentingStream(socket, chunkSize, ownsSocket: true, delay)
                                : new NetworkStream(socket, ownsSocket: true);
                            transferred = true;
                            return stream;
                        }
                        catch (SocketException)
                        {
                            // Try next IP.
                        }
                        finally
                        {
                            if (!transferred)
                            {
                                socket.Dispose();
                            }
                        }
                    }

                    throw new SocketException((int)SocketError.HostNotFound);
                };
            }

            HttpMessageInvoker invoker = new(handler, disposeHandler: true);
            handler = null;
            return invoker;
        }
        finally
        {
            handler?.Dispose();
        }
    }

    private static (Uri TargetUri, Uri? RelayUri) ResolveTargetAndRelayUris(DnsServerEntry upstream)
    {
        Uri? targetUri = null;
        Uri? relayUri = null;

        if (!string.IsNullOrWhiteSpace(upstream.DohUrl))
        {
            string raw = upstream.DohUrl.Trim();
            if (raw.StartsWith("odoh://", StringComparison.OrdinalIgnoreCase))
            {
                raw = string.Concat("https://", raw["odoh://".Length..]);
            }

            targetUri = new Uri(raw, UriKind.Absolute);
        }

        if (EndpointResolutionHelper.TryGetParsedStamp(upstream, out DnsStamp? stamp) && stamp is not null)
        {
            if (stamp.Protocol == DnsStampProtocol.ObliviousDoHTarget && targetUri is null)
            {
                string path = string.IsNullOrWhiteSpace(stamp.Path) ? "/dns-query" : stamp.Path;
                targetUri = new Uri(string.Concat("https://", stamp.HostName, path), UriKind.Absolute);
            }
            else if (stamp.Protocol == DnsStampProtocol.ObliviousDoHRelay)
            {
                string path = string.IsNullOrWhiteSpace(stamp.Path) ? "/proxy" : stamp.Path;
                relayUri = new Uri(string.Concat("https://", stamp.HostName, path), UriKind.Absolute);
            }
        }

        string? relaySource = !string.IsNullOrWhiteSpace(upstream.SmartProxyIp)
            ? upstream.SmartProxyIp
            : upstream.SecondaryIp;

        if (relayUri is null && !string.IsNullOrWhiteSpace(relaySource))
        {
            string trimmedRelay = relaySource.Trim();
            if (trimmedRelay.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                || trimmedRelay.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                relayUri = new Uri(trimmedRelay, UriKind.Absolute);
            }
            else if (DnsStampCodec.TryParse(trimmedRelay, out DnsStamp? relayStamp)
                && relayStamp is not null
                && relayStamp.Protocol == DnsStampProtocol.ObliviousDoHRelay)
            {
                string path = string.IsNullOrWhiteSpace(relayStamp.Path) ? "/proxy" : relayStamp.Path;
                relayUri = new Uri(string.Concat("https://", relayStamp.HostName, path), UriKind.Absolute);
            }
        }

        if (targetUri is null)
        {
            throw new InvalidOperationException($"ODoH upstream '{upstream.Name}' does not specify a target URI or ODoH Target stamp.");
        }

        return (targetUri, relayUri);
    }

    private static Uri BuildRelayPostUri(Uri relayUri, Uri targetUri)
    {
        string separator = string.IsNullOrEmpty(relayUri.Query) ? "?" : "&";
        string path = string.IsNullOrEmpty(targetUri.AbsolutePath) ? "/dns-query" : targetUri.AbsolutePath;
        return new Uri(
            string.Concat(
                relayUri.AbsoluteUri,
                separator,
                "targethost=",
                Uri.EscapeDataString(targetUri.Authority),
                "&targetpath=",
                Uri.EscapeDataString(path)),
            UriKind.Absolute);
    }
}
