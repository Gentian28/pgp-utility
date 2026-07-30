using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using PgpUtility.Models;

namespace PgpUtility.Services;

public class PgpService : IPgpService
{
    /// <summary>
    /// The symmetric cipher used for the session key and for protecting a secret key at rest.
    /// AES-256 everywhere: a 128 bit block, so no birthday bound to worry about on large files,
    /// and it is what the key's own self-signature advertises.
    /// </summary>
    private const SymmetricKeyAlgorithmTag SessionCipher = SymmetricKeyAlgorithmTag.Aes256;

    /// <summary>
    /// Miller-Rabin rounds for RSA prime generation. The old value of 12 left a 1 in 4096 chance
    /// of accepting a composite. The extra rounds are lost in the noise next to finding the
    /// candidates in the first place.
    /// </summary>
    private const int RsaPrimeCertainty = 128;

    private const int BufferSize = 1 << 16;

    public async Task<OperationResult> EncryptFileAsync(
        string inputFilePath,
        string outputFilePath,
        string publicKeySource,
        bool isFilePath,
        bool armor,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report($"Encrypting {Path.GetFileName(inputFilePath)}...");

                PgpPublicKey encKey = isFilePath
                    ? ReadPublicKeyFromFile(publicKeySource)
                    : ReadPublicKeyFromString(publicKeySource);

                using Stream outputStream = File.Create(outputFilePath);

                if (armor)
                {
                    using var armoredStream = new ArmoredOutputStream(outputStream);
                    Encrypt(inputFilePath, armoredStream, encKey);
                }
                else
                {
                    Encrypt(inputFilePath, outputStream, encKey);
                }

                progress?.Report($"Encrypted {Path.GetFileName(inputFilePath)} successfully.");
                return OperationResult.Succeeded(
                    $"File encrypted successfully: {Path.GetFileName(outputFilePath)}",
                    outputFilePath);
            }
            catch (OperationCanceledException)
            {
                TryDeleteFile(outputFilePath);
                return OperationResult.Failed("Encryption cancelled.");
            }
            catch (Exception ex)
            {
                TryDeleteFile(outputFilePath);
                return OperationResult.Failed($"Encryption failed: {ex.Message}");
            }
        }, cancellationToken);
    }

    public async Task<OperationResult> DecryptFileAsync(
        string inputFilePath,
        string outputFilePath,
        string privateKeySource,
        bool isFilePath,
        char[] passphrase,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report($"Decrypting {Path.GetFileName(inputFilePath)}...");

                using Stream input = File.OpenRead(inputFilePath);
                using Stream keyIn = isFilePath
                    ? File.OpenRead(privateKeySource)
                    : new MemoryStream(Encoding.UTF8.GetBytes(privateKeySource));

                bool integrityProtected = Decrypt(input, keyIn, passphrase, outputFilePath);

                progress?.Report($"Decrypted {Path.GetFileName(inputFilePath)} successfully.");
                return OperationResult.Succeeded(
                    $"File decrypted successfully: {Path.GetFileName(outputFilePath)}",
                    outputFilePath,
                    integrityProtected
                        ? null
                        : $"{Path.GetFileName(inputFilePath)} carried no integrity check, so there is no way to tell whether it was altered after it was encrypted. Trust its contents only as far as you trust where it came from.");
            }
            catch (OperationCanceledException)
            {
                TryDeleteFile(outputFilePath);
                return OperationResult.Failed("Decryption cancelled.");
            }
            catch (Exception ex)
            {
                TryDeleteFile(outputFilePath);
                return OperationResult.Failed($"Decryption failed: {ex.Message}");
            }
        }, cancellationToken);
    }

    public async Task<(string PublicKey, string PrivateKey)> GenerateKeyPairAsync(
        KeyGenerationOptions options,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        // Work from a private copy. Generation runs on a worker thread and the caller is entitled
        // to zero its own array the instant this returns.
        char[] passphrase = (char[])options.Passphrase.Clone();

        try
        {
            return await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                var random = new SecureRandom();

                // One timestamp for the key packet and for the expiry offset. Reading the clock
                // twice leaves the expiry a few milliseconds out from the creation time it is
                // measured against.
                DateTime now = DateTime.UtcNow;

                PgpPublicKeyRing publicRing;
                PgpSecretKeyRing secretRing;

                if (options.Algorithm == PgpKeyAlgorithm.Ed25519)
                {
                    progress?.Report("Generating Ed25519 key pair...");
                    (publicRing, secretRing) = GenerateEd25519(options, passphrase, now, random, progress, cancellationToken);
                }
                else
                {
                    progress?.Report($"Generating {options.KeySize}-bit RSA key pair...");
                    (publicRing, secretRing) = GenerateRsa(options, passphrase, now, random, progress, cancellationToken);
                }

                progress?.Report("Exporting keys...");
                cancellationToken.ThrowIfCancellationRequested();

                string publicKey = Armor(publicRing.Encode);
                string privateKey = Armor(secretRing.Encode);

                progress?.Report("Key pair generated successfully.");
                return (publicKey, privateKey);
            }, cancellationToken);
        }
        finally
        {
            Array.Clear(passphrase);
        }
    }

    public PgpKeyInfo ReadPublicKeyInfo(string keySource, bool isFilePath)
    {
        using Stream keyIn = OpenKeySource(keySource, isFilePath);
        using Stream decoderStream = PgpUtilities.GetDecoderStream(keyIn);

        var bundle = new PgpPublicKeyRingBundle(decoderStream);
        foreach (PgpPublicKeyRing ring in bundle.GetKeyRings())
        {
            PgpPublicKey masterKey = ring.GetPublicKeys().Cast<PgpPublicKey>().First();
            return Describe(masterKey, hasPrivateKey: false);
        }

        throw new ArgumentException("No public key found in key data.");
    }

    public PgpKeyInfo ReadPrivateKeyInfo(string keySource, bool isFilePath)
    {
        using Stream keyIn = OpenKeySource(keySource, isFilePath);
        using Stream decoderStream = PgpUtilities.GetDecoderStream(keyIn);

        var bundle = new PgpSecretKeyRingBundle(decoderStream);
        foreach (PgpSecretKeyRing ring in bundle.GetKeyRings())
        {
            PgpSecretKey masterKey = ring.GetSecretKeys().Cast<PgpSecretKey>().First();
            return Describe(masterKey.PublicKey, hasPrivateKey: true);
        }

        throw new ArgumentException("No secret key found in key data.");
    }

    public string ExtractPublicKeyFromPrivateKey(string privateKeySource, bool isFilePath)
    {
        using Stream keyIn = OpenKeySource(privateKeySource, isFilePath);
        using Stream decoderStream = PgpUtilities.GetDecoderStream(keyIn);

        var bundle = new PgpSecretKeyRingBundle(decoderStream);
        foreach (PgpSecretKeyRing ring in bundle.GetKeyRings())
        {
            return Armor(output =>
            {
                foreach (PgpSecretKey secretKey in ring.GetSecretKeys())
                    secretKey.PublicKey.Encode(output);
            });
        }

        throw new ArgumentException("No secret key found in key data.");
    }

    // --- Key generation ---

    private static (PgpPublicKeyRing Public, PgpSecretKeyRing Secret) GenerateRsa(
        KeyGenerationOptions options,
        char[] passphrase,
        DateTime now,
        SecureRandom random,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        var kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");
        kpg.Init(new RsaKeyGenerationParameters(
            BigInteger.ValueOf(65537),
            random,
            options.KeySize,
            RsaPrimeCertainty));

        AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
        cancellationToken.ThrowIfCancellationRequested();

        progress?.Report("Building PGP key ring...");

        // A single RSA key that certifies, signs and encrypts. GnuPG would split this into a
        // master and an encryption subkey, but that means generating two 4096-bit keys and so
        // roughly doubles the wait. Kept as one key; Ed25519 below has the conventional shape,
        // because there both halves are effectively free.
        var masterKey = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kp, now);

        var hashed = new PgpSignatureSubpacketGenerator();
        hashed.SetKeyFlags(false,
            PgpKeyFlags.CanSign |
            PgpKeyFlags.CanCertify |
            PgpKeyFlags.CanEncryptCommunications |
            PgpKeyFlags.CanEncryptStorage);
        ApplyCommonPreferences(hashed, options, now);

        var ringGen = new PgpKeyRingGenerator(
            PgpSignature.DefaultCertification,
            masterKey,
            options.Identity,
            SessionCipher,
            HashAlgorithmTag.Sha256,
            utf8PassPhrase: true,
            passphrase,
            useSha1: true,
            hashed.Generate(),
            null,
            random);

        return (ringGen.GeneratePublicKeyRing(), ringGen.GenerateSecretKeyRing());
    }

    private static (PgpPublicKeyRing Public, PgpSecretKeyRing Secret) GenerateEd25519(
        KeyGenerationOptions options,
        char[] passphrase,
        DateTime now,
        SecureRandom random,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        // Ed25519 signs, it cannot encrypt. A usable key therefore has to be a ring: an Ed25519
        // master that certifies and signs, plus a Curve25519 subkey that receives encryption.
        // EdDsa_Legacy is algorithm 22, the encoding GnuPG 2.1 through 2.4 and effectively every
        // deployed implementation reads. The RFC 9580 Ed25519 tag is newer than the tools.
        var edGen = new Ed25519KeyPairGenerator();
        edGen.Init(new Ed25519KeyGenerationParameters(random));
        var masterKey = new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa_Legacy, edGen.GenerateKeyPair(), now);

        cancellationToken.ThrowIfCancellationRequested();
        progress?.Report("Generating Curve25519 encryption subkey...");

        var xGen = new X25519KeyPairGenerator();
        xGen.Init(new X25519KeyGenerationParameters(random));
        var encryptionSubKey = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, xGen.GenerateKeyPair(), now);

        cancellationToken.ThrowIfCancellationRequested();
        progress?.Report("Building PGP key ring...");

        var masterPackets = new PgpSignatureSubpacketGenerator();
        masterPackets.SetKeyFlags(false, PgpKeyFlags.CanSign | PgpKeyFlags.CanCertify);
        ApplyCommonPreferences(masterPackets, options, now);

        var subKeyPackets = new PgpSignatureSubpacketGenerator();
        subKeyPackets.SetKeyFlags(false,
            PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
        if (options.ExpirationDate.HasValue)
            SetExpiry(subKeyPackets, options.ExpirationDate.Value, now);

        var ringGen = new PgpKeyRingGenerator(
            PgpSignature.DefaultCertification,
            masterKey,
            options.Identity,
            SessionCipher,
            HashAlgorithmTag.Sha256,
            utf8PassPhrase: true,
            passphrase,
            useSha1: true,
            masterPackets.Generate(),
            null,
            random);

        ringGen.AddSubKey(encryptionSubKey, subKeyPackets.Generate(), null);

        return (ringGen.GeneratePublicKeyRing(), ringGen.GenerateSecretKeyRing());
    }

    private static void ApplyCommonPreferences(
        PgpSignatureSubpacketGenerator hashed,
        KeyGenerationOptions options,
        DateTime now)
    {
        hashed.SetPreferredHashAlgorithms(false, new[]
        {
            (int)HashAlgorithmTag.Sha256,
            (int)HashAlgorithmTag.Sha384,
            (int)HashAlgorithmTag.Sha512
        });

        // CAST5 is deliberately absent. This list is what we tell other implementations they may
        // encrypt to us with, and advertising a 64-bit block cipher invites exactly the weakness
        // that was just removed from the sending side.
        hashed.SetPreferredSymmetricAlgorithms(false, new[]
        {
            (int)SymmetricKeyAlgorithmTag.Aes256,
            (int)SymmetricKeyAlgorithmTag.Aes192,
            (int)SymmetricKeyAlgorithmTag.Aes128
        });

        hashed.SetPreferredCompressionAlgorithms(false, new[]
        {
            (int)CompressionAlgorithmTag.ZLib,
            (int)CompressionAlgorithmTag.Zip,
            (int)CompressionAlgorithmTag.Uncompressed
        });

        // Announces that this key understands modification detection. Without it a sender that
        // follows the spec strictly may fall back to an unauthenticated packet, which undoes the
        // integrity guarantee at the other end of the conversation.
        hashed.SetFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        if (options.ExpirationDate.HasValue)
            SetExpiry(hashed, options.ExpirationDate.Value, now);
    }

    private static void SetExpiry(PgpSignatureSubpacketGenerator packets, DateTime expiry, DateTime now)
    {
        long seconds = (long)(expiry - now).TotalSeconds;
        if (seconds > 0)
            packets.SetKeyExpirationTime(false, seconds);
    }

    // --- Encryption and decryption ---

    private static void Encrypt(string inputFilePath, Stream outputStream, PgpPublicKey encKey)
    {
        // withIntegrityPacket is fixed at true and is not a caller choice. An OpenPGP message
        // without a modification detection code is malleable: an attacker who cannot read the
        // plaintext can still flip chosen bits in it and the recipient has no way to notice.
        var encGen = new PgpEncryptedDataGenerator(SessionCipher, withIntegrityPacket: true, new SecureRandom());
        encGen.AddMethod(encKey);

        using Stream encryptedOut = encGen.Open(outputStream, new byte[BufferSize]);
        var compGen = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
        using Stream compressedOut = compGen.Open(encryptedOut);
        PgpUtilities.WriteFileToLiteralData(compressedOut, PgpLiteralData.Binary, new FileInfo(inputFilePath), new byte[BufferSize]);
    }

    /// <returns>
    /// True if the message carried an integrity check and it verified. False if the message had
    /// no integrity check at all. A check that is present and fails throws instead.
    /// </returns>
    private static bool Decrypt(Stream inputStream, Stream keyIn, char[] passPhrase, string outputFilePath)
    {
        inputStream = PgpUtilities.GetDecoderStream(inputStream);
        var pgpObjFactory = new PgpObjectFactory(inputStream);

        PgpObject o = pgpObjFactory.NextPgpObject();
        PgpEncryptedDataList enc = o is PgpEncryptedDataList list
            ? list
            : (PgpEncryptedDataList)pgpObjFactory.NextPgpObject();

        var pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));

        PgpPrivateKey? sKey = null;
        PgpPublicKeyEncryptedData? pbe = null;

        foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>())
        {
            PgpSecretKey? secretKey = pgpSec.GetSecretKey(pked.KeyId);
            if (secretKey == null)
                continue;

            sKey = ExtractPrivateKey(secretKey, passPhrase);
            pbe = pked;
            break;
        }

        if (pbe == null || sKey == null)
            throw new PgpException(
                "this file was not encrypted to the key you selected. Pick the private key matching the public key it was encrypted with.");

        // The plaintext goes to a temporary file first. The integrity check can only be verified
        // once the whole stream has been read, so writing straight to the destination would leave
        // altered plaintext sitting at the path the user asked for, even for the moment it takes
        // to delete it again.
        string tempPath = outputFilePath + ".partial";
        bool integrityProtected;

        try
        {
            using (Stream clear = pbe.GetDataStream(sKey))
            {
                var plainFact = new PgpObjectFactory(clear);

                if (UnwrapToLiteral(plainFact) is not PgpLiteralData ld)
                    throw new PgpException("the message decrypted but does not contain a file.");

                using (Stream unc = ld.GetInputStream())
                using (Stream outStream = File.Create(tempPath))
                {
                    Streams.PipeAll(unc, outStream);
                }

                // Verify inside the using block: it drains whatever is left of the encrypted
                // stream to reach the trailing MDC packet, so the stream has to still be open.
                integrityProtected = pbe.IsIntegrityProtected();
                if (integrityProtected && !pbe.Verify())
                {
                    throw new IntegrityCheckFailedException(
                        "the integrity check failed. This file was altered after it was encrypted, so the decrypted output has been discarded.");
                }
            }

            File.Move(tempPath, outputFilePath, overwrite: true);
            return integrityProtected;
        }
        finally
        {
            TryDeleteFile(tempPath);
        }
    }

    private static PgpPrivateKey ExtractPrivateKey(PgpSecretKey secretKey, char[] passPhrase)
    {
        try
        {
            // GnuPG encodes passphrases as UTF-8, so this is the path that matters for interop
            // and the one this app writes with.
            return secretKey.ExtractPrivateKeyUtf8(passPhrase);
        }
        catch (PgpException utf8Failure) when (IsPassphraseFailure(utf8Failure))
        {
            try
            {
                // BouncyCastle's older default wrote one byte per char. Identical for ASCII,
                // different beyond it, so a key protected that way still opens here.
                return secretKey.ExtractPrivateKey(passPhrase);
            }
            catch (PgpException legacyFailure) when (IsPassphraseFailure(legacyFailure))
            {
                throw new IncorrectPassphraseException(
                    "incorrect passphrase for this key. Check caps lock and your keyboard layout, then try again.",
                    legacyFailure);
            }
        }
    }

    /// <summary>
    /// Distinguishes a bad passphrase from a key this build cannot handle at all. BouncyCastle
    /// reports both as PgpException, and telling a user to retype their passphrase when the real
    /// problem is an unsupported algorithm sends them round in circles.
    /// </summary>
    private static bool IsPassphraseFailure(PgpException ex) =>
        ex.Message.Contains("checksum mismatch", StringComparison.OrdinalIgnoreCase) ||
        ex.Message.Contains("Exception decrypting key", StringComparison.OrdinalIgnoreCase);

    private static PgpObject? UnwrapToLiteral(PgpObjectFactory factory)
    {
        PgpObject? obj = factory.NextPgpObject();
        while (obj != null)
        {
            switch (obj)
            {
                case PgpCompressedData compressed:
                    return UnwrapToLiteral(new PgpObjectFactory(compressed.GetDataStream()));
                case PgpOnePassSignatureList:
                case PgpSignatureList:
                case PgpMarker:
                    obj = factory.NextPgpObject();
                    break;
                case PgpLiteralData:
                    return obj;
                default:
                    throw new PgpException($"unsupported PGP object type: {obj.GetType().Name}.");
            }
        }
        return null;
    }

    // --- Reading keys ---

    private static PgpKeyInfo Describe(PgpPublicKey key, bool hasPrivateKey) => new()
    {
        KeyId = $"0x{key.KeyId:X16}",
        UserId = key.GetUserIds().Cast<string>().FirstOrDefault() ?? "Unknown",
        Fingerprint = Convert.ToHexString(key.GetFingerprint()),
        Algorithm = key.Algorithm.ToString(),
        KeySize = key.BitStrength,
        CreationDate = key.CreationTime,
        ExpirationDate = key.GetValidSeconds() > 0
            ? key.CreationTime.AddSeconds(key.GetValidSeconds())
            : null,
        HasPrivateKey = hasPrivateKey
    };

    private static Stream OpenKeySource(string keySource, bool isFilePath) => isFilePath
        ? File.OpenRead(keySource)
        : new MemoryStream(Encoding.UTF8.GetBytes(keySource));

    private static PgpPublicKey ReadPublicKeyFromFile(string filePath)
    {
        using Stream keyIn = File.OpenRead(filePath);
        return ReadPublicKeyFromStream(keyIn);
    }

    private static PgpPublicKey ReadPublicKeyFromString(string publicKey)
    {
        using Stream keyIn = new MemoryStream(Encoding.UTF8.GetBytes(publicKey));
        return ReadPublicKeyFromStream(keyIn);
    }

    private static PgpPublicKey ReadPublicKeyFromStream(Stream keyIn)
    {
        using Stream inputStream = PgpUtilities.GetDecoderStream(keyIn);
        var publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);

        foreach (PgpPublicKeyRing keyRing in publicKeyRingBundle.GetKeyRings())
        {
            foreach (PgpPublicKey key in keyRing.GetPublicKeys())
            {
                if (key.IsEncryptionKey)
                    return key;
            }
        }

        throw new ArgumentException("No encryption key found in public key ring.");
    }

    private static string Armor(Action<Stream> encode)
    {
        using var buffer = new MemoryStream();
        using (var armoredOut = new ArmoredOutputStream(buffer))
        {
            encode(armoredOut);
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
