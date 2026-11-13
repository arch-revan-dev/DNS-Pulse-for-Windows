using System.Buffers.Binary;
using System.Text;
using DnsPulse.Engine.Sidecar;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Sidecar;

public sealed class TlsClientHelloInspectorTests
{
    [Fact]
    public void Inspect_Tls12ClientHelloWithSni_FindsExactSniAndHostnameOffsets()
    {
        byte[] hello = BuildSyntheticClientHello(
            hostname: "api.openai.com",
            includeGrease: false,
            includeEch: false,
            legacyRecordMinor: 0x01);

        bool ok = TlsClientHelloInspector.TryInspect(hello, out TlsClientHelloInspection inspection);

        ok.Should().BeTrue();
        inspection.IsTlsClientHello.Should().BeTrue();
        inspection.IsTruncated.Should().BeFalse();
        inspection.HasSni.Should().BeTrue();
        inspection.HasEchExtension.Should().BeFalse();
        inspection.ServerName.Should().Be("api.openai.com");

        // Verify SNI extension header starts with 0x00, 0x00
        hello.AsSpan(inspection.SniExtensionOffset, 2).ToArray().Should().Equal(0x00, 0x00);
        int declaredExtDataLen = BinaryPrimitives.ReadUInt16BigEndian(hello.AsSpan(inspection.SniExtensionOffset + 2, 2));
        inspection.SniExtensionLength.Should().Be(4 + declaredExtDataLen);

        // Verify ServerName slice matches exact ASCII bytes
        string extracted = Encoding.ASCII.GetString(hello, inspection.ServerNameOffset, inspection.ServerNameLength);
        extracted.Should().Be("api.openai.com");
    }

    [Fact]
    public void Inspect_Tls13ClientHelloWithGreaseAndEch_FindsSniAndFlagsEch()
    {
        byte[] hello = BuildSyntheticClientHello(
            hostname: "gemini.google.com",
            includeGrease: true,
            includeEch: true,
            legacyRecordMinor: 0x03);

        TlsClientHelloInspection inspection = TlsClientHelloInspector.Inspect(hello);

        inspection.IsTlsClientHello.Should().BeTrue();
        inspection.IsTruncated.Should().BeFalse();
        inspection.HasSni.Should().BeTrue();
        inspection.HasEchExtension.Should().BeTrue();
        inspection.ServerName.Should().Be("gemini.google.com");

        string extracted = Encoding.ASCII.GetString(hello, inspection.ServerNameOffset, inspection.ServerNameLength);
        extracted.Should().Be("gemini.google.com");
    }

    [Fact]
    public void Inspect_ClientHelloWithoutSni_ReturnsHasSniFalse()
    {
        byte[] hello = BuildSyntheticClientHello(
            hostname: null,
            includeGrease: true,
            includeEch: false,
            legacyRecordMinor: 0x01);

        TlsClientHelloInspection inspection = TlsClientHelloInspector.Inspect(hello);

        inspection.IsTlsClientHello.Should().BeTrue();
        inspection.IsTruncated.Should().BeFalse();
        inspection.HasSni.Should().BeFalse();
        inspection.SniExtensionOffset.Should().Be(-1);
        inspection.SniExtensionLength.Should().Be(0);
        inspection.ServerName.Should().BeNull();
    }

    [Fact]
    public void Inspect_EveryTruncatedPrefix_NeverThrowsAndFlagsTruncated()
    {
        byte[] hello = BuildSyntheticClientHello(
            hostname: "claude.ai",
            includeGrease: true,
            includeEch: false,
            legacyRecordMinor: 0x01);

        for (int len = 0; len < hello.Length; len++)
        {
            ReadOnlySpan<byte> slice = hello.AsSpan(0, len);
            TlsClientHelloInspection inspection = TlsClientHelloInspector.Inspect(slice);

            if (len < 6)
            {
                inspection.IsTlsClientHello.Should().BeFalse();
            }
            else
            {
                inspection.IsTlsClientHello.Should().BeTrue();
                inspection.IsTruncated.Should().BeTrue();
            }
        }
    }

    [Fact]
    public void Inspect_NonTlsTraffic_ReturnsNotClientHello()
    {
        byte[] httpGet = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"u8.ToArray();
        byte[] tlsServerHello = [0x16, 0x03, 0x03, 0x00, 0x08, 0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00];
        byte[] tlsAppData = [0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];

        TlsClientHelloInspector.TryInspect(httpGet, out TlsClientHelloInspection r1).Should().BeFalse();
        r1.IsTlsClientHello.Should().BeFalse();

        TlsClientHelloInspector.TryInspect(tlsServerHello, out TlsClientHelloInspection r2).Should().BeFalse();
        r2.IsTlsClientHello.Should().BeFalse();

        TlsClientHelloInspector.TryInspect(tlsAppData, out TlsClientHelloInspection r3).Should().BeFalse();
        r3.IsTlsClientHello.Should().BeFalse();
    }

    internal static byte[] BuildSyntheticClientHello(
        string? hostname,
        bool includeGrease,
        bool includeEch,
        byte legacyRecordMinor = 0x01)
    {
        List<byte> extensions = [];

        if (includeGrease)
        {
            // GREASE extension 0x0A0A with 0-byte payload
            extensions.AddRange([0x0A, 0x0A, 0x00, 0x00]);
            // supported_groups (0x000A) with GREASE group 0x1A1A + x25519 (0x001D)
            extensions.AddRange([0x00, 0x0A, 0x00, 0x06, 0x00, 0x04, 0x1A, 0x1A, 0x00, 0x1D]);
        }

        if (!string.IsNullOrEmpty(hostname))
        {
            byte[] hostBytes = Encoding.ASCII.GetBytes(hostname);
            int listLen = 3 + hostBytes.Length;
            int extLen = 2 + listLen;

            extensions.Add(0x00);
            extensions.Add(0x00);
            extensions.Add((byte)(extLen >> 8));
            extensions.Add((byte)extLen);
            extensions.Add((byte)(listLen >> 8));
            extensions.Add((byte)listLen);
            extensions.Add(0x00); // host_name
            extensions.Add((byte)(hostBytes.Length >> 8));
            extensions.Add((byte)hostBytes.Length);
            extensions.AddRange(hostBytes);
        }

        if (includeEch)
        {
            // Synthetic ECH extension 0xFE0D (8 bytes dummy payload)
            extensions.AddRange([0xFE, 0x0D, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        }

        // supported_versions (0x002B) = TLS 1.3 (0x0304)
        extensions.AddRange([0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04]);

        List<byte> body =
        [
            0x03, 0x03 // legacy_version TLS 1.2
        ];

        // 32-byte random
        for (int i = 0; i < 32; i++)
        {
            body.Add((byte)(0xA0 + i));
        }

        // 32-byte session id
        body.Add(0x20);
        for (int i = 0; i < 32; i++)
        {
            body.Add((byte)(0x10 + i));
        }

        // Cipher suites: optional GREASE + TLS_AES_128_GCM_SHA256 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        if (includeGrease)
        {
            body.AddRange([0x00, 0x06, 0x2A, 0x2A, 0x13, 0x01, 0xC0, 0x2F]);
        }
        else
        {
            body.AddRange([0x00, 0x04, 0x13, 0x01, 0xC0, 0x2F]);
        }

        // Compression methods: 1 method (null = 0x00)
        body.AddRange([0x01, 0x00]);

        // Extensions total length + payload
        body.Add((byte)(extensions.Count >> 8));
        body.Add((byte)extensions.Count);
        body.AddRange(extensions);

        int handshakeLen = body.Count;
        int recordLen = 4 + handshakeLen;

        byte[] record = new byte[5 + recordLen];
        record[0] = 0x16; // Handshake
        record[1] = 0x03;
        record[2] = legacyRecordMinor;
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3, 2), (ushort)recordLen);
        record[5] = 0x01; // ClientHello
        record[6] = (byte)(handshakeLen >> 16);
        record[7] = (byte)(handshakeLen >> 8);
        record[8] = (byte)handshakeLen;
        body.CopyTo(record, 9);

        return record;
    }
}
