using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DnsPulse.Engine.Transports;

/// <summary>
/// Provides strict X.509 chain/SAN validation and SPKI SHA-256 pinning helpers for TLS-backed DNS transports.
/// </summary>
public static class TlsCertificateValidator
{
    /// <summary>
    /// Computes the Base64-encoded SHA-256 hash of a certificate's SubjectPublicKeyInfo (SPKI).
    /// </summary>
    public static string ComputeSpkiPinSha256Base64(X509Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        byte[] hash = ComputeSpkiPinSha256Bytes(certificate);
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// Computes the raw 32-byte SHA-256 hash of a certificate's SubjectPublicKeyInfo (SPKI).
    /// </summary>
    public static byte[] ComputeSpkiPinSha256Bytes(X509Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        if (certificate is X509Certificate2 cert2)
        {
            byte[] spki = cert2.PublicKey.ExportSubjectPublicKeyInfo();
            return SHA256.HashData(spki);
        }

        using X509Certificate2 loaded = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        byte[] loadedSpki = loaded.PublicKey.ExportSubjectPublicKeyInfo();
        return SHA256.HashData(loadedSpki);
    }

    /// <summary>
    /// Parses a Base64 (with optional <c>sha256//</c> prefix) or 64-character hex SPKI SHA-256 pin into 32 raw bytes.
    /// </summary>
    public static bool TryParseSpkiPin(string? pin, out byte[] pinBytes)
    {
        if (string.IsNullOrWhiteSpace(pin))
        {
            pinBytes = [];
            return false;
        }

        string trimmed = pin.Trim();
        if (trimmed.StartsWith("sha256//", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed["sha256//".Length..].Trim();
        }
        else if (trimmed.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed["sha256:".Length..].Trim();
        }

        if (trimmed.Length == 64 && IsHexString(trimmed))
        {
            pinBytes = Convert.FromHexString(trimmed);
            return pinBytes.Length == 32;
        }

        try
        {
            byte[] decoded = Convert.FromBase64String(trimmed);
            if (decoded.Length == 32)
            {
                pinBytes = decoded;
                return true;
            }
        }
        catch (FormatException)
        {
            // Fall through to base64url check.
        }

        string base64 = trimmed.Replace('-', '+').Replace('_', '/');
        int pad = base64.Length % 4;
        if (pad == 2)
        {
            base64 = string.Concat(base64, "==");
        }
        else if (pad == 3)
        {
            base64 = string.Concat(base64, "=");
        }
        else if (pad == 1)
        {
            pinBytes = [];
            return false;
        }

        try
        {
            byte[] decodedUrl = Convert.FromBase64String(base64);
            if (decodedUrl.Length == 32)
            {
                pinBytes = decodedUrl;
                return true;
            }
        }
        catch (FormatException)
        {
            pinBytes = [];
            return false;
        }

        pinBytes = [];
        return false;
    }

    internal static X509ChainPolicy? BuildCustomChainPolicy(X509Certificate2Collection? customTrustAnchors)
    {
        if (customTrustAnchors is null || customTrustAnchors.Count == 0)
        {
            return null;
        }

        X509ChainPolicy policy = new()
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck
        };
        policy.CustomTrustStore.AddRange(customTrustAnchors);
        return policy;
    }

    internal static bool ValidateServerCertificate(
        X509Certificate? certificate,
        SslPolicyErrors sslPolicyErrors,
        string? expectedSpkiPinSha256)
    {
        if (sslPolicyErrors != SslPolicyErrors.None || certificate is null)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(expectedSpkiPinSha256))
        {
            return true;
        }

        if (!TryParseSpkiPin(expectedSpkiPinSha256, out byte[] expectedBytes))
        {
            return false;
        }

        byte[] actualBytes = ComputeSpkiPinSha256Bytes(certificate);
        return CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
    }

    private static bool IsHexString(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            bool isHex = c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');
            if (!isHex)
            {
                return false;
            }
        }

        return true;
    }
}
