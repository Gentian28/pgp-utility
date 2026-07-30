using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
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
    public async Task<OperationResult> EncryptFileAsync(
        string inputFilePath,
        string outputFilePath,
        string publicKeySource,
        bool isFilePath,
        bool armor,
        bool withIntegrityCheck,
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
                    Encrypt(inputFilePath, armoredStream, encKey, withIntegrityCheck);
                }
                else
                {
                    Encrypt(inputFilePath, outputStream, encKey, withIntegrityCheck);
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
        string passphrase,
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

                Decrypt(input, keyIn, passphrase, outputFilePath);

                progress?.Report($"Decrypted {Path.GetFileName(inputFilePath)} successfully.");
                return OperationResult.Succeeded(
                    $"File decrypted successfully: {Path.GetFileName(outputFilePath)}",
                    outputFilePath);
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
        return await Task.Run(() =>
        {
            progress?.Report("Generating RSA key pair...");
            cancellationToken.ThrowIfCancellationRequested();

            var kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpg.Init(new RsaKeyGenerationParameters(
                BigInteger.ValueOf(65537),
                new SecureRandom(),
                options.KeySize,
                12));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            progress?.Report("Building PGP key ring...");
            cancellationToken.ThrowIfCancellationRequested();

            var hashedGen = new PgpSignatureSubpacketGenerator();
            hashedGen.SetKeyFlags(false,
                PgpKeyFlags.CanSign |
                PgpKeyFlags.CanCertify |
                PgpKeyFlags.CanEncryptCommunications |
                PgpKeyFlags.CanEncryptStorage);
            hashedGen.SetPreferredHashAlgorithms(false, new[]
            {
                (int)HashAlgorithmTag.Sha256,
                (int)HashAlgorithmTag.Sha384,
                (int)HashAlgorithmTag.Sha512
            });
            hashedGen.SetPreferredSymmetricAlgorithms(false, new[]
            {
                (int)SymmetricKeyAlgorithmTag.Aes256,
                (int)SymmetricKeyAlgorithmTag.Aes192,
                (int)SymmetricKeyAlgorithmTag.Aes128,
                (int)SymmetricKeyAlgorithmTag.Cast5
            });

            if (options.ExpirationDate.HasValue)
            {
                long seconds = (long)(options.ExpirationDate.Value - DateTime.UtcNow).TotalSeconds;
                if (seconds > 0)
                    hashedGen.SetKeyExpirationTime(false, seconds);
            }

            PgpSecretKey secretKey = new PgpSecretKey(
                PgpSignature.DefaultCertification,
                PublicKeyAlgorithmTag.RsaGeneral,
                kp.Public,
                kp.Private,
                DateTime.UtcNow,
                options.Identity,
                SymmetricKeyAlgorithmTag.Cast5,
                options.Passphrase.ToCharArray(),
                hashedGen.Generate(),
                null,
                new SecureRandom());

            progress?.Report("Exporting keys...");
            cancellationToken.ThrowIfCancellationRequested();

            string publicKey;
            using (var pubOut = new MemoryStream())
            {
                using (var armoredOut = new ArmoredOutputStream(pubOut))
                {
                    secretKey.PublicKey.Encode(armoredOut);
                }
                publicKey = Encoding.UTF8.GetString(pubOut.ToArray());
            }

            string privateKey;
            using (var secOut = new MemoryStream())
            {
                using (var armoredOut = new ArmoredOutputStream(secOut))
                {
                    secretKey.Encode(armoredOut);
                }
                privateKey = Encoding.UTF8.GetString(secOut.ToArray());
            }

            progress?.Report("Key pair generated successfully.");
            return (publicKey, privateKey);
        }, cancellationToken);
    }

    public PgpKeyInfo ReadPublicKeyInfo(string keySource, bool isFilePath)
    {
        using Stream keyIn = isFilePath
            ? File.OpenRead(keySource)
            : new MemoryStream(Encoding.UTF8.GetBytes(keySource));
        using Stream decoderStream = PgpUtilities.GetDecoderStream(keyIn);

        var bundle = new PgpPublicKeyRingBundle(decoderStream);
        foreach (PgpPublicKeyRing ring in bundle.GetKeyRings())
        {
            PgpPublicKey masterKey = ring.GetPublicKeys().Cast<PgpPublicKey>().First();
            string userId = masterKey.GetUserIds().Cast<string>().FirstOrDefault() ?? "Unknown";

            return new PgpKeyInfo
            {
                KeyId = $"0x{masterKey.KeyId:X16}",
                UserId = userId,
                Fingerprint = BitConverter.ToString(masterKey.GetFingerprint()).Replace("-", ""),
                Algorithm = masterKey.Algorithm.ToString(),
                KeySize = masterKey.BitStrength,
                CreationDate = masterKey.CreationTime,
                ExpirationDate = masterKey.GetValidSeconds() > 0
                    ? masterKey.CreationTime.AddSeconds(masterKey.GetValidSeconds())
                    : null,
                HasPrivateKey = false
            };
        }

        throw new ArgumentException("No public key found in key data.");
    }

    public PgpKeyInfo ReadPrivateKeyInfo(string keySource, bool isFilePath, string? passphrase = null)
    {
        using Stream keyIn = isFilePath
            ? File.OpenRead(keySource)
            : new MemoryStream(Encoding.UTF8.GetBytes(keySource));
        using Stream decoderStream = PgpUtilities.GetDecoderStream(keyIn);

        var bundle = new PgpSecretKeyRingBundle(decoderStream);
        foreach (PgpSecretKeyRing ring in bundle.GetKeyRings())
        {
            PgpSecretKey masterKey = ring.GetSecretKeys().Cast<PgpSecretKey>().First();
            string userId = masterKey.PublicKey.GetUserIds().Cast<string>().FirstOrDefault() ?? "Unknown";

            return new PgpKeyInfo
            {
                KeyId = $"0x{masterKey.KeyId:X16}",
                UserId = userId,
                Fingerprint = BitConverter.ToString(masterKey.PublicKey.GetFingerprint()).Replace("-", ""),
                Algorithm = masterKey.PublicKey.Algorithm.ToString(),
                KeySize = masterKey.PublicKey.BitStrength,
                CreationDate = masterKey.PublicKey.CreationTime,
                ExpirationDate = masterKey.PublicKey.GetValidSeconds() > 0
                    ? masterKey.PublicKey.CreationTime.AddSeconds(masterKey.PublicKey.GetValidSeconds())
                    : null,
                HasPrivateKey = true
            };
        }

        throw new ArgumentException("No secret key found in key data.");
    }

    public string ExtractPublicKeyFromPrivateKey(string privateKeySource, bool isFilePath)
    {
        using Stream keyIn = isFilePath
            ? File.OpenRead(privateKeySource)
            : new MemoryStream(Encoding.UTF8.GetBytes(privateKeySource));
        using Stream decoderStream = PgpUtilities.GetDecoderStream(keyIn);

        var bundle = new PgpSecretKeyRingBundle(decoderStream);
        foreach (PgpSecretKeyRing ring in bundle.GetKeyRings())
        {
            using var pubOut = new MemoryStream();
            using (var armoredOut = new ArmoredOutputStream(pubOut))
            {
                foreach (PgpSecretKey secretKey in ring.GetSecretKeys())
                {
                    secretKey.PublicKey.Encode(armoredOut);
                }
            }
            return Encoding.UTF8.GetString(pubOut.ToArray());
        }

        throw new ArgumentException("No secret key found in key data.");
    }

    // --- Private helpers (ported from ByteForge) ---

    private static void Encrypt(string inputFilePath, Stream outputStream, PgpPublicKey encKey, bool withIntegrityCheck)
    {
        var encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
        encGen.AddMethod(encKey);

        using Stream encryptedOut = encGen.Open(outputStream, new byte[1 << 16]);
        var compGen = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
        using Stream compressedOut = compGen.Open(encryptedOut);
        PgpUtilities.WriteFileToLiteralData(compressedOut, PgpLiteralData.Binary, new FileInfo(inputFilePath), new byte[1 << 16]);
    }

    private static void Decrypt(Stream inputStream, Stream keyIn, string passPhrase, string outputFilePath)
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
            sKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());
            if (sKey != null)
            {
                pbe = pked;
                break;
            }
        }

        if (pbe == null || sKey == null)
            throw new PgpException("Secret key for message not found.");

        using Stream clear = pbe.GetDataStream(sKey);
        var plainFact = new PgpObjectFactory(clear);

        PgpObject? message = UnwrapToLiteral(plainFact);
        if (message is not PgpLiteralData ld)
            throw new PgpException($"Message is not a simple file. Actual type: {message?.GetType().FullName ?? "null"}");

        using Stream unc = ld.GetInputStream();
        using Stream outStream = File.Create(outputFilePath);
        Streams.PipeAll(unc, outStream);
    }

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
                    throw new PgpException($"Unsupported PGP object type: {obj.GetType().Name}");
            }
        }
        return null;
    }

    private static PgpPrivateKey? FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
    {
        PgpSecretKey? pgpSecKey = pgpSec.GetSecretKey(keyId);
        return pgpSecKey?.ExtractPrivateKey(pass);
    }

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

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
