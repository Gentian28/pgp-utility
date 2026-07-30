using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpUtility.Models;

namespace PgpUtility.Services;

public class PgpSignatureService : IPgpSignatureService
{
    private const HashAlgorithmTag SignatureHash = HashAlgorithmTag.Sha256;
    private const int BufferSize = 1 << 16;

    public async Task<OperationResult> SignFileAsync(
        string inputFilePath,
        string signatureFilePath,
        string privateKeySource,
        bool isFilePath,
        char[] passphrase,
        bool armor,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report($"Signing {Path.GetFileName(inputFilePath)}...");

                PgpSignatureGenerator generator = StartSigning(
                    privateKeySource, isFilePath, passphrase, PgpSignature.BinaryDocument);

                using (Stream input = File.OpenRead(inputFilePath))
                {
                    Feed(generator, input, cancellationToken);
                }

                PgpSignature signature = generator.Generate();

                using (Stream output = File.Create(signatureFilePath))
                {
                    if (armor)
                    {
                        using var armored = new ArmoredOutputStream(output);
                        signature.Encode(armored);
                    }
                    else
                    {
                        signature.Encode(output);
                    }
                }

                progress?.Report("Signed.");
                return OperationResult.Succeeded(
                    $"Signature written to {Path.GetFileName(signatureFilePath)}",
                    signatureFilePath);
            }
            catch (OperationCanceledException)
            {
                TryDeleteFile(signatureFilePath);
                return OperationResult.Failed("Signing cancelled.");
            }
            catch (Exception ex)
            {
                TryDeleteFile(signatureFilePath);
                return OperationResult.Failed($"Signing failed: {ex.Message}");
            }
        }, cancellationToken);
    }

    public async Task<SignatureVerification> VerifyFileAsync(
        string inputFilePath,
        string signatureFilePath,
        string publicKeySource,
        bool isFilePath,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report($"Verifying {Path.GetFileName(inputFilePath)}...");

                using Stream signatureIn = PgpUtilities.GetDecoderStream(File.OpenRead(signatureFilePath));
                PgpSignature? signature = FirstSignature(new PgpObjectFactory(signatureIn));

                if (signature is null)
                    return SignatureVerification.Failed("That file does not contain a signature.");

                using Stream keyIn = OpenKeySource(publicKeySource, isFilePath);
                var bundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));

                PgpPublicKey? signerKey = bundle.GetPublicKey(signature.KeyId);
                if (signerKey is null)
                {
                    return SignatureVerification.Invalid(
                        $"Signed by key 0x{signature.KeyId:X16}, which is not the key you selected. Import the signer's public key and try again.",
                        $"0x{signature.KeyId:X16}");
                }

                signature.InitVerify(signerKey);

                using (Stream input = File.OpenRead(inputFilePath))
                {
                    Feed(signature, input, cancellationToken);
                }

                return Describe(signature, signerKey, Path.GetFileName(inputFilePath), signature.Verify());
            }
            catch (OperationCanceledException)
            {
                return SignatureVerification.Failed("Verification cancelled.");
            }
            catch (Exception ex)
            {
                return SignatureVerification.Failed($"Verification failed: {ex.Message}");
            }
        }, cancellationToken);
    }

    public async Task<OperationResult> SignTextAsync(
        string text,
        string privateKeySource,
        bool isFilePath,
        char[] passphrase,
        CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            try
            {
                // CanonicalTextDocument, not BinaryDocument: a clear-signed message is going to
                // travel through mail clients and chat apps that rewrite line endings, and the
                // canonical form is what makes the signature survive that.
                PgpSignatureGenerator generator = StartSigning(
                    privateKeySource, isFilePath, passphrase, PgpSignature.CanonicalTextDocument);

                string[] lines = text.Replace("\r\n", "\n").Split('\n');

                using var output = new MemoryStream();
                using (var armored = new ArmoredOutputStream(output))
                {
                    armored.BeginClearText(SignatureHash);

                    for (int i = 0; i < lines.Length; i++)
                    {
                        // Trailing whitespace is not part of what gets signed in canonical text
                        // form, so it must not be hashed either, or the signature will not verify
                        // in any other implementation.
                        string line = lines[i].TrimEnd();
                        byte[] bytes = Encoding.UTF8.GetBytes(line);

                        if (i > 0)
                        {
                            generator.Update((byte)'\r');
                            generator.Update((byte)'\n');
                        }

                        generator.Update(bytes);

                        armored.Write(Encoding.UTF8.GetBytes(lines[i]));
                        armored.Write("\r\n"u8.ToArray());
                    }

                    armored.EndClearText();

                    using var bcpg = new BcpgOutputStream(armored);
                    generator.Generate().Encode(bcpg);
                }

                return OperationResult.Succeeded("Text signed.")
                    with { Payload = Encoding.UTF8.GetString(output.ToArray()) };
            }
            catch (Exception ex)
            {
                return OperationResult.Failed($"Signing failed: {ex.Message}");
            }
        }, cancellationToken);
    }

    public async Task<SignatureVerification> VerifyTextAsync(
        string clearSignedText,
        string publicKeySource,
        bool isFilePath,
        CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            try
            {
                using var input = new MemoryStream(Encoding.UTF8.GetBytes(clearSignedText));
                using var armoredIn = new ArmoredInputStream(input);

                // Read back the signed text exactly as the armor layer presents it, applying the
                // same canonical rules used when signing.
                var signedBytes = new MemoryStream();
                int character = armoredIn.ReadByte();
                var lineBuffer = new MemoryStream();
                bool firstLine = true;

                while (character >= 0 && armoredIn.IsClearText())
                {
                    if (character == '\n')
                    {
                        AppendCanonicalLine(signedBytes, lineBuffer, ref firstLine);
                    }
                    else if (character != '\r')
                    {
                        lineBuffer.WriteByte((byte)character);
                    }
                    character = armoredIn.ReadByte();
                }

                if (lineBuffer.Length > 0)
                    AppendCanonicalLine(signedBytes, lineBuffer, ref firstLine);

                PgpSignature? signature = FirstSignature(new PgpObjectFactory(armoredIn));
                if (signature is null)
                    return SignatureVerification.Failed("That text does not contain a signature.");

                using Stream keyIn = OpenKeySource(publicKeySource, isFilePath);
                var bundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));

                PgpPublicKey? signerKey = bundle.GetPublicKey(signature.KeyId);
                if (signerKey is null)
                {
                    return SignatureVerification.Invalid(
                        $"Signed by key 0x{signature.KeyId:X16}, which is not the key you selected. Import the signer's public key and try again.",
                        $"0x{signature.KeyId:X16}");
                }

                signature.InitVerify(signerKey);
                signature.Update(signedBytes.ToArray());

                return Describe(signature, signerKey, "this message", signature.Verify());
            }
            catch (Exception ex)
            {
                return SignatureVerification.Failed($"Verification failed: {ex.Message}");
            }
        }, cancellationToken);
    }

    // --- Helpers ---

    private static void AppendCanonicalLine(MemoryStream signedBytes, MemoryStream lineBuffer, ref bool firstLine)
    {
        byte[] line = lineBuffer.ToArray();
        lineBuffer.SetLength(0);

        // Trim trailing whitespace, matching what the signer hashed.
        int end = line.Length;
        while (end > 0 && (line[end - 1] == ' ' || line[end - 1] == '\t')) end--;

        if (!firstLine)
            signedBytes.Write("\r\n"u8);
        firstLine = false;

        signedBytes.Write(line, 0, end);
    }

    private static PgpSignatureGenerator StartSigning(
        string privateKeySource, bool isFilePath, char[] passphrase, int signatureType)
    {
        using Stream keyIn = OpenKeySource(privateKeySource, isFilePath);
        var bundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));

        PgpSecretKey secretKey = PgpKeyRoles.FindSigningKey(bundle);
        PgpPrivateKey privateKey = PgpKeyRoles.ExtractPrivateKey(secretKey, passphrase);

        var generator = new PgpSignatureGenerator(secretKey.PublicKey.Algorithm, SignatureHash);
        generator.InitSign(signatureType, privateKey);

        // Records who signed, so a verifier can show a name rather than a bare key id even before
        // the key is looked up. Unhashed would let anyone rewrite it, so it goes in the hashed
        // area where it is covered by the signature.
        if (PgpKeyRoles.PrimaryUserId(secretKey.PublicKey) is { } userId)
        {
            var packets = new PgpSignatureSubpacketGenerator();
            packets.AddSignerUserId(false, userId);
            generator.SetHashedSubpackets(packets.Generate());
        }

        return generator;
    }

    private static SignatureVerification Describe(
        PgpSignature signature, PgpPublicKey signerKey, string what, bool valid)
    {
        string keyId = $"0x{signature.KeyId:X16}";
        string? userId = PgpKeyRoles.PrimaryUserId(signerKey);

        if (!valid)
        {
            return SignatureVerification.Invalid(
                $"The signature does not match {what}. Either the file changed after it was signed, or the signature belongs to a different file.",
                keyId);
        }

        // A good signature from a key that should no longer be used is still a fact about the
        // bytes, so it is reported as valid with a caveat rather than quietly downgraded.
        string? caveat = null;
        if (signerKey.IsRevoked())
        {
            caveat = "The signing key has been revoked. The signature is genuine, but its owner has retired the key.";
        }
        else if (signerKey.GetValidSeconds() > 0 &&
                 signerKey.CreationTime.AddSeconds(signerKey.GetValidSeconds()) < DateTime.UtcNow)
        {
            caveat = "The signing key has expired. The signature is genuine, and may have been made before it expired.";
        }

        return SignatureVerification.Valid(
            $"Good signature from {userId ?? keyId}.",
            keyId, userId, signature.CreationTime, caveat);
    }

    private static PgpSignature? FirstSignature(PgpObjectFactory factory)
    {
        PgpObject? o = factory.NextPgpObject();
        while (o != null)
        {
            switch (o)
            {
                // Signature files are sometimes compressed, gpg's --sign among them.
                case PgpCompressedData compressed:
                    return FirstSignature(new PgpObjectFactory(compressed.GetDataStream()));
                case PgpSignatureList list when list.Count > 0:
                    return list[0];
                default:
                    o = factory.NextPgpObject();
                    break;
            }
        }
        return null;
    }

    private static void Feed(PgpSignatureGenerator generator, Stream input, CancellationToken cancellationToken)
    {
        var buffer = new byte[BufferSize];
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            generator.Update(buffer, 0, read);
        }
    }

    private static void Feed(PgpSignature signature, Stream input, CancellationToken cancellationToken)
    {
        var buffer = new byte[BufferSize];
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            signature.Update(buffer, 0, read);
        }
    }

    private static Stream OpenKeySource(string keySource, bool isFilePath) => isFilePath
        ? File.OpenRead(keySource)
        : new MemoryStream(Encoding.UTF8.GetBytes(keySource));

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
