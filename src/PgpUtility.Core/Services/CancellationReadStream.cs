namespace PgpUtility.Services;

/// <summary>Checks cancellation even when a crypto decoder drains its input internally.</summary>
internal sealed class CancellationReadStream(Stream input, CancellationToken cancellationToken) : Stream
{
    public override bool CanRead => input.CanRead;
    public override bool CanSeek => input.CanSeek;
    public override bool CanWrite => false;
    public override long Length => input.Length;
    public override long Position { get => input.Position; set => input.Position = value; }
    public override int Read(byte[] buffer, int offset, int count)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return input.Read(buffer, offset, count);
    }
    public override int Read(Span<byte> buffer)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return input.Read(buffer);
    }
    public override int ReadByte()
    {
        cancellationToken.ThrowIfCancellationRequested();
        return input.ReadByte();
    }
    public override long Seek(long offset, SeekOrigin origin) => input.Seek(offset, origin);
    public override void Flush() => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    // The caller retains ownership of the input stream.
}
