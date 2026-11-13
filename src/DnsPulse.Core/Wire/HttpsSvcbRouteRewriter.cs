namespace DnsPulse.Core.Wire;

/// <summary>
/// Rewrites DNS answers for IPv4-only Geo-Unlock / SNI-Proxy routing while preserving ECH and SVCB/HTTPS on Direct paths.
/// </summary>
public static class HttpsSvcbRouteRewriter
{
    /// <summary>
    /// Rewrites a DNS message according to the selected routing mode.
    /// When <paramref name="geoUnlockIpv4Only"/> is true: strips <c>AAAA (28)</c> answers (producing a valid
    /// <c>NOERROR</c> NODATA response if no answers remain), and strips <c>ipv4hint (4)</c>, <c>ipv6hint (6)</c>,
    /// and <c>alpn=h3</c> (preserving <c>h2</c>/<c>http/1.1</c>) inside <c>SVCB (64)</c>/<c>HTTPS (65)</c> records.
    /// When <paramref name="geoUnlockIpv4Only"/> is false (Direct): preserves <c>HTTPS (65)</c>/<c>SVCB (64)</c> intact including <c>ech (5)</c>.
    /// </summary>
    public static DnsMessage Rewrite(DnsMessage message, bool geoUnlockIpv4Only)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (!geoUnlockIpv4Only)
        {
            return message;
        }

        List<DnsResourceRecord> rewrittenAnswers = RewriteSection(message.Answers);
        List<DnsResourceRecord> rewrittenAdditionals = RewriteSection(message.Additionals);

        DnsResponseCode responseCode = rewrittenAnswers.Count == 0 && message.Header.ResponseCode == DnsResponseCode.NoError
            ? DnsResponseCode.NoError
            : message.Header.ResponseCode;

        if (rewrittenAnswers.Count == 0 && message.Answers.Count > 0 && message.Answers.All(a => a.RecordType == DnsRecordType.AAAA))
        {
            responseCode = DnsResponseCode.NoError;
        }

        return message with
        {
            Header = message.Header with
            {
                ResponseCode = responseCode,
                AnswerCount = (ushort)rewrittenAnswers.Count,
                AdditionalCount = (ushort)rewrittenAdditionals.Count
            },
            Answers = rewrittenAnswers,
            Additionals = rewrittenAdditionals
        };
    }

    private static List<DnsResourceRecord> RewriteSection(IReadOnlyList<DnsResourceRecord> section)
    {
        List<DnsResourceRecord> result = new(section.Count);
        foreach (DnsResourceRecord record in section)
        {
            if (record.RecordType == DnsRecordType.AAAA)
            {
                continue;
            }

            if (record.RecordType is DnsRecordType.SVCB or DnsRecordType.HTTPS)
            {
                result.Add(RewriteServiceBindingRecord(record));
                continue;
            }

            result.Add(record);
        }

        return result;
    }

    private static DnsResourceRecord RewriteServiceBindingRecord(DnsResourceRecord record)
    {
        if (record.SvcParams.Count == 0)
        {
            return record;
        }

        List<SvcParam> filtered = new(record.SvcParams.Count);
        HashSet<ushort> removedKeys =
        [
            (ushort)SvcParamKey.Ipv4Hint,
            (ushort)SvcParamKey.Ipv6Hint
        ];

        foreach (SvcParam param in record.SvcParams)
        {
            if (param.Key is (ushort)SvcParamKey.Ipv4Hint or (ushort)SvcParamKey.Ipv6Hint)
            {
                continue;
            }

            if (param.Key == (ushort)SvcParamKey.Alpn)
            {
                IReadOnlyList<string> alpnIds = param.ParseAlpnIds();
                List<string> keptAlpn = new(alpnIds.Count);
                foreach (string id in alpnIds)
                {
                    if (string.Equals(id, "h3", StringComparison.OrdinalIgnoreCase)
                        || id.StartsWith("h3-", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    keptAlpn.Add(id);
                }

                if (keptAlpn.Count > 0)
                {
                    filtered.Add(SvcParam.CreateAlpn(keptAlpn));
                }
                else
                {
                    removedKeys.Add((ushort)SvcParamKey.Alpn);
                }

                continue;
            }

            filtered.Add(param);
        }

        // Prune removed keys from Mandatory (key 0) if present so the rewritten RR remains RFC 9460 compliant.
        for (int index = 0; index < filtered.Count; index++)
        {
            if (filtered[index].Key != (ushort)SvcParamKey.Mandatory)
            {
                continue;
            }

            IReadOnlyList<ushort> mandatoryKeys = filtered[index].ParseMandatoryKeys();
            List<ushort> keptMandatory = [];
            foreach (ushort key in mandatoryKeys)
            {
                if (!removedKeys.Contains(key))
                {
                    keptMandatory.Add(key);
                }
            }

            if (keptMandatory.Count > 0)
            {
                filtered[index] = SvcParam.CreateMandatory(keptMandatory);
            }
            else
            {
                filtered.RemoveAt(index);
            }

            break;
        }

        return record.WithSvcParams(filtered);
    }
}
