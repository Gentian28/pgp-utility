using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpUtility.Models;

namespace PgpUtility.Services;

/// <summary>Validates certificate ownership before a packet is used as somebody's key.</summary>
internal sealed class PgpKeyValidation
{
    private readonly Dictionary<long, (PgpPublicKey Key, PgpSignature Certification)> _keys = new();
    private readonly PgpSignature _primaryCertification;

    public PgpPublicKeyRing Ring { get; }
    public PgpPublicKey Primary => Ring.GetPublicKey();
    public string UserId { get; }
    public string Fingerprint => Convert.ToHexString(Primary.GetFingerprint());
    public IReadOnlyDictionary<string, PgpSignature> IdentityCertifications { get; }
    public PgpSignature CertificationFor(PgpPublicKey key) => _keys[key.KeyId].Certification;
    public bool IsRevoked => HasRevocation(Primary, PgpSignature.KeyRevocation);
    public DateTime? ExpirationDate => Expiry(Primary, _primaryCertification);

    public static PgpPublicKeyRing ReadPublic(Stream source)
    {
        CryptoInputLimits.CheckKey(source);
        using var decoder = PgpUtilities.GetDecoderStream(source);
        var rings = new PgpPublicKeyRingBundle(decoder).GetKeyRings().ToArray();
        if (rings.Length != 1)
            throw new PgpException("Select a file containing exactly one public key identity.");
        return rings[0];
    }

    public static PgpSecretKeyRing ReadSecret(Stream source)
    {
        CryptoInputLimits.CheckKey(source);
        using var decoder = PgpUtilities.GetDecoderStream(source);
        var rings = new PgpSecretKeyRingBundle(decoder).GetKeyRings().ToArray();
        if (rings.Length != 1)
            throw new PgpException("Select a file containing exactly one private key identity.");
        return rings[0];
    }

    public static PgpPublicKeyRing PublicRing(PgpSecretKeyRing secret)
    {
        using var buffer = new MemoryStream();
        foreach (var key in secret.GetPublicKeys()) key.Encode(buffer);
        return new PgpPublicKeyRing(buffer.ToArray());
    }

    public PgpKeyValidation(PgpPublicKeyRing ring)
    {
        Ring = ring;
        if (!Primary.IsMasterKey || !PgpKeyRoles.CanSign(Primary.Algorithm))
            throw new PgpException("This certificate has no supported certifying primary key.");

        var identities = new List<(string Id, PgpSignature Signature)>();
        foreach (string id in Primary.GetUserIds())
        {
            var certificates = Primary.GetSignaturesForId(id).Where(s =>
                s.SignatureType is >= PgpSignature.DefaultCertification and <= PgpSignature.PositiveCertification &&
                Check(s, Primary, () => s.VerifyCertification(id, Primary))).ToArray();
            var latest = certificates.OrderByDescending(s => s.CreationTime).FirstOrDefault();
            if (latest is null) continue;
            bool revoked = Primary.GetSignaturesForId(id).Any(s =>
                s.SignatureType == PgpSignature.CertificationRevocation && s.CreationTime >= latest.CreationTime &&
                Check(s, Primary, () => s.VerifyCertification(id, Primary)));
            if (!revoked) identities.Add((id, latest));
        }

        if (identities.Count == 0)
            throw new PgpException("The key has no identity with a valid self-certification.");
        IdentityCertifications = identities.ToDictionary(i => i.Id, i => i.Signature, StringComparer.Ordinal);
        _primaryCertification = identities.OrderByDescending(i => i.Signature.CreationTime).First().Signature;
        UserId = identities.OrderByDescending(i => i.Signature.GetHashedSubPackets()?.IsPrimaryUserId() == true)
            .ThenByDescending(i => i.Signature.CreationTime).First().Id;
        _keys.Add(Primary.KeyId, (Primary, _primaryCertification));

        foreach (var key in ring.GetPublicKeys().Where(k => !k.IsMasterKey))
        {
            var binding = key.GetSignaturesOfType(PgpSignature.SubkeyBinding)
                .Where(s => Check(s, Primary, () => s.VerifyCertification(Primary, key)))
                .OrderByDescending(s => s.CreationTime).FirstOrDefault();
            if (binding is null)
                throw new PgpException("An encryption or signing subkey has no valid binding to the primary fingerprint. Do not use this key file.");
            if (!_keys.TryAdd(key.KeyId, (key, binding)))
                throw new PgpException("This key contains ambiguous duplicate key IDs.");
        }
        // Validate revocation semantics while the complete certificate is still being loaded,
        // so unsupported requirements cannot survive import or crash a later metadata refresh.
        _ = IsRevoked;
        foreach (var key in ring.GetPublicKeys().Where(k => !k.IsMasterKey))
            _ = HasRevocation(key, PgpSignature.SubkeyRevocation);
    }

    public PgpPublicKey EncryptionKey() => _keys.Values
        .Where(k => k.Key.IsEncryptionKey && Allows(k.Certification, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage))
        .Where(k => IsLive(k.Key, k.Certification))
        .OrderBy(k => k.Key.IsMasterKey).ThenByDescending(k => k.Key.CreationTime)
        .Select(k => k.Key).FirstOrDefault()
        ?? throw new PgpException("No current, unrevoked encryption key is available for this identity.");

    public PgpSecretKey SigningKey(PgpSecretKeyRing secret)
    {
        foreach (var candidate in _keys.Values.OrderBy(k => k.Key.IsMasterKey).ThenByDescending(k => k.Key.CreationTime))
        {
            if (!PgpKeyRoles.CanSign(candidate.Key.Algorithm) || !Allows(candidate.Certification, PgpKeyFlags.CanSign) ||
                !IsLive(candidate.Key, candidate.Certification) || !HasSigningBinding(candidate.Key, candidate.Certification)) continue;
            var key = secret.GetSecretKey(candidate.Key.GetFingerprint());
            if (key is not null && !key.IsPrivateKeyEmpty) return key;
        }
        throw new PgpException("No current, unrevoked signing key with an available private half was found.");
    }

    public PgpPublicKey? VerificationKey(long id)
    {
        if (!_keys.TryGetValue(id, out var candidate)) return null;
        return PgpKeyRoles.CanSign(candidate.Key.Algorithm) && Allows(candidate.Certification, PgpKeyFlags.CanSign) &&
            HasSigningBinding(candidate.Key, candidate.Certification) ? candidate.Key : null;
    }

    public string? Caveat(PgpPublicKey signingKey)
    {
        var certification = _keys[signingKey.KeyId].Certification;
        if (IsRevoked || (!signingKey.IsMasterKey && HasRevocation(signingKey, PgpSignature.SubkeyRevocation)))
            return "The primary key or signing subkey has been revoked. Do not rely on this signature without investigating the revocation.";
        if (!IsLive(signingKey, certification))
            return "The primary key, signing subkey or its certification has expired. Check when this signature was made.";
        return null;
    }

    public PgpKeyInfo Describe(bool hasPrivateKey, PgpSecretKeyRing? secret = null) => new()
    {
        KeyId = $"0x{Primary.KeyId:X16}", UserId = UserId, Fingerprint = Fingerprint,
        Algorithm = Primary.Algorithm.ToString(), KeySize = Primary.BitStrength,
        CreationDate = Primary.CreationTime, ExpirationDate = ExpirationDate,
        HasPrivateKey = hasPrivateKey, IsRevoked = IsRevoked,
        CanEncrypt = _keys.Values.Any(k => k.Key.IsEncryptionKey && Allows(k.Certification,
            PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage) && IsLive(k.Key, k.Certification)),
        CanSign = _keys.Values.Any(k => PgpKeyRoles.CanSign(k.Key.Algorithm) && Allows(k.Certification, PgpKeyFlags.CanSign) &&
            IsLive(k.Key, k.Certification) && HasSigningBinding(k.Key, k.Certification) &&
            (secret is null || secret.GetSecretKey(k.Key.GetFingerprint()) is { IsPrivateKeyEmpty: false }))
    };

    private bool IsLive(PgpPublicKey key, PgpSignature certification)
    {
        var now = DateTime.UtcNow;
        return !IsRevoked && !HasExpired(Primary, _primaryCertification, now) &&
            !HasExpired(key, certification, now) && key.CreationTime <= now &&
            (key.IsMasterKey || !HasRevocation(key, PgpSignature.SubkeyRevocation));
    }

    private bool HasRevocation(PgpPublicKey key, int type) => key.GetSignaturesOfType(type).Any(s =>
        Check(s, Primary, () => key.IsMasterKey ? s.VerifyCertification(Primary) : s.VerifyCertification(Primary, key)));

    private bool HasSigningBinding(PgpPublicKey key, PgpSignature binding)
    {
        if (key.IsMasterKey) return true;
        // Older tools place the embedded signature in the unhashed area. It is independently
        // verified with the subkey, so its location does not substitute for ownership proof.
        foreach (var packets in new[] { binding.GetHashedSubPackets(), binding.GetUnhashedSubPackets() })
        {
            var embedded = packets?.GetEmbeddedSignatures();
            if (embedded is null) continue;
            for (int i = 0; i < embedded.Count; i++)
            {
                var signature = embedded[i];
                if (signature.SignatureType == PgpSignature.PrimaryKeyBinding &&
                    Check(signature, key, () => signature.VerifyCertification(Primary, key))) return true;
            }
        }
        return false;
    }

    private static bool Allows(PgpSignature certification, int flags)
    {
        var packets = certification.GetHashedSubPackets();
        // Missing flags on older certificates mean algorithm capability. An explicit flag
        // list, including zero, is authoritative and must not be replaced with that fallback.
        return packets?.HasSubpacket(SignatureSubpacketTag.KeyFlags) != true || (packets.GetKeyFlags() & flags) != 0;
    }

    private static DateTime? Expiry(PgpPublicKey key, PgpSignature certification)
    {
        long seconds = certification.GetHashedSubPackets()?.GetKeyExpirationTime() ?? 0;
        return seconds > 0 ? AddSeconds(key.CreationTime, seconds) : null;
    }

    private static bool HasExpired(PgpPublicKey key, PgpSignature certification, DateTime now)
    {
        long seconds = certification.GetHashedSubPackets()?.GetSignatureExpirationTime() ?? 0;
        return (Expiry(key, certification) is { } expiry && expiry <= now) ||
            (seconds > 0 && AddSeconds(certification.CreationTime, seconds) <= now);
    }

    private static DateTime AddSeconds(DateTime time, long seconds) =>
        seconds > (DateTime.MaxValue - time).TotalSeconds ? DateTime.MaxValue : time.AddSeconds(seconds);

    private static bool Check(PgpSignature signature, PgpPublicKey issuer, Func<bool> verify)
    {
        if (signature.CreationTime > DateTime.UtcNow || signature.CreationTime < issuer.CreationTime) return false;
        try { signature.InitVerify(issuer); if (!verify()) return false; }
        catch (PgpException) { return false; }
        var critical = signature.GetHashedSubPackets()?.GetCriticalTags() ?? [];
        // A valid but unsupported requirement is a failure of the complete certificate.
        // Ignoring it would silently fall back to an older, less restrictive certification.
        if (critical.Any(tag => (int)tag is not (2 or 3 or 9 or 11 or 16 or 21 or 22 or 25 or 27 or 29 or 30 or 32 or 33)))
            throw new PgpException("This certificate has authenticated critical requirements this app cannot interpret. Use a specialist tool to inspect it.");
        return true;
    }
}
