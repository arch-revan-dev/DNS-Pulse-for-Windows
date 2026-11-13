using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DnsPulse.Engine.Tests.Transports;

internal static class MockTlsServerHelper
{
    public static X509Certificate2 CreateSelfSignedServerCertificate(string dnsName, IPAddress? sanIp = null)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(
            $"CN={dnsName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.KeyCertSign,
                critical: true));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                [new Oid("1.3.6.1.5.5.7.3.1")],
                critical: false));

        SubjectAlternativeNameBuilder sanBuilder = new();
        sanBuilder.AddDnsName(dnsName);
        if (sanIp is not null)
        {
            sanBuilder.AddIpAddress(sanIp);
        }

        request.CertificateExtensions.Add(sanBuilder.Build());

        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 ephemeral = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(7));
        byte[] pfxBytes = ephemeral.Export(X509ContentType.Pfx, "test-pfx");
        return X509CertificateLoader.LoadPkcs12(pfxBytes, "test-pfx", X509KeyStorageFlags.Exportable);
    }
}
