using Hoddmir.Core.Encryption.AEAD;
using Hoddmir.Memory;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Hoddmir.Storage;

/// <summary>Encodes and authenticates one mutation in the encrypted log.</summary>
internal sealed class EncryptedRecordCodec
{
    #region Const

    private const int SaltLength = 32;
    private const int KeyLength = 32;
    private const int TagLength = 16;
    private const int PrefixLength = 13;
    private const int HeaderLength = SaltLength + PrefixLength + TagLength;
    private const int RecordOverhead = HeaderLength + TagLength;
    private const int MaxPadding = 64;

    #endregion

    #region Fields

    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly IAEADProvider aead;

    #endregion

    #region Properties

    private static ReadOnlySpan<byte> PrefixNonce => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    private static ReadOnlySpan<byte> PayloadNonce => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    #endregion

    #region .ctor

    /// <summary>Creates a codec using the store's AEAD provider.</summary>
    public EncryptedRecordCodec(IAEADProvider aead) => this.aead = aead;

    #endregion

    #region Methods

    /// <summary>Encrypts a put or tombstone for the specified absolute file offset.</summary>
    public byte[] Encode(SensitiveBytes dek, long offset, string id, ReadOnlySpan<byte> value, bool deleted)
    {
        int idLength = Utf8.GetByteCount(id);
        int contentLength = checked(idLength + value.Length);
        int paddedLength = checked(contentLength + RandomNumberGenerator.GetInt32(MaxPadding + 1));
        byte[] record = new byte[checked(RecordOverhead + paddedLength)];
        byte[] payload = new byte[paddedLength];
        Span<byte> recordKey = stackalloc byte[KeyLength];
        Span<byte> prefix = stackalloc byte[PrefixLength];
        Span<byte> position = stackalloc byte[sizeof(long)];
        Span<byte> salt = record.AsSpan(0, SaltLength);
        Span<byte> encryptedPrefix = record.AsSpan(SaltLength, PrefixLength + TagLength);

        try
        {
            Utf8.GetBytes(id.AsSpan(), payload);
            value.CopyTo(payload.AsSpan(idLength));
            RandomNumberGenerator.Fill(payload.AsSpan(contentLength));
            RandomNumberGenerator.Fill(salt);
            DeriveKey(dek, salt, recordKey);

            prefix[0] = deleted ? (byte)1 : (byte)0;
            BinaryPrimitives.WriteInt32LittleEndian(prefix[1..], idLength);
            BinaryPrimitives.WriteInt32LittleEndian(prefix[5..], contentLength);
            BinaryPrimitives.WriteInt32LittleEndian(prefix[9..], paddedLength);
            BinaryPrimitives.WriteInt64LittleEndian(position, offset);

            this.aead.Encrypt(recordKey, PrefixNonce, position, prefix,
                              encryptedPrefix[..PrefixLength], encryptedPrefix[PrefixLength..]);
            this.aead.Encrypt(recordKey, PayloadNonce, encryptedPrefix, payload,
                              record.AsSpan(HeaderLength, paddedLength), record.AsSpan(HeaderLength + paddedLength));
            return record;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recordKey);
            CryptographicOperations.ZeroMemory(prefix);
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    /// <summary>Reads and authenticates a record, distinguishing incomplete tails from corrupt records.</summary>
    public async Task<RecordRead> ReadAsync(IAppendOnlyStoreProvider store, SensitiveBytes dek,
                                            long offset, long end, bool includeValue, CancellationToken ct)
    {
        if (end - offset < RecordOverhead)
            return new(ReadStatus.Truncated);

        byte[] header = new byte[HeaderLength];
        if (!await ReadExactlyAsync(store, offset, header, ct).ConfigureAwait(false))
            return new(ReadStatus.Truncated);

        byte[] recordKey = new byte[KeyLength];
        try
        {
            DeriveKey(dek, header.AsSpan(0, SaltLength), recordKey);
            if (!this.TryReadPrefix(header, recordKey, offset, out RecordPrefix prefix))
                return new(ReadStatus.Corrupt);

            int length = RecordOverhead + prefix.PaddedLength;
            if (length > end - offset)
                return new(ReadStatus.Truncated);

            byte[] body = new byte[prefix.PaddedLength + TagLength];
            if (!await ReadExactlyAsync(store, offset + HeaderLength, body, ct).ConfigureAwait(false))
                return new(ReadStatus.Truncated);

            return this.DecodeBody(header, body, recordKey, prefix, length, includeValue);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recordKey);
        }
    }

    /// <summary>Fills a read buffer unless the backend reaches the end of its data.</summary>
    public static async Task<bool> ReadExactlyAsync(IAppendOnlyStoreProvider store, long offset,
                                                    Memory<byte> buffer, CancellationToken ct)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int count = await store.ReadAtAsync(offset + read, buffer[read..], ct).ConfigureAwait(false);
            if (count == 0)
                return false;

            read += count;
        }

        return true;
    }

    /// <summary>Derives the key used solely for the record with this salt.</summary>
    private static void DeriveKey(SensitiveBytes dek, ReadOnlySpan<byte> salt, Span<byte> output) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, dek.AsSpan(), output, salt, "Hoddmir/0x01/record"u8);

    /// <summary>Authenticates the prefix and validates lengths before any body allocation.</summary>
    private bool TryReadPrefix(ReadOnlySpan<byte> header, ReadOnlySpan<byte> key, long offset, out RecordPrefix prefix)
    {
        prefix = default;
        Span<byte> plaintext = stackalloc byte[PrefixLength];
        Span<byte> position = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64LittleEndian(position, offset);

        try
        {
            if (!this.TryDecrypt(key, PrefixNonce, position, header.Slice(SaltLength, PrefixLength),
                                 header[(SaltLength + PrefixLength)..], plaintext))
                return false;

            byte operation = plaintext[0];
            int idLength = BinaryPrimitives.ReadInt32LittleEndian(plaintext[1..]);
            int contentLength = BinaryPrimitives.ReadInt32LittleEndian(plaintext[5..]);
            int paddedLength = BinaryPrimitives.ReadInt32LittleEndian(plaintext[9..]);

            if (operation > 1 || idLength <= 0 || contentLength < idLength ||
                paddedLength < contentLength || paddedLength - contentLength > MaxPadding ||
                paddedLength > Array.MaxLength - RecordOverhead ||
                (operation == 1 && contentLength != idLength))
                return false;

            prefix = new(operation == 1, idLength, contentLength, paddedLength);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>Authenticates the body and returns its ID and optional value.</summary>
    private RecordRead DecodeBody(ReadOnlySpan<byte> header, ReadOnlySpan<byte> body, ReadOnlySpan<byte> key,
                                  RecordPrefix prefix, int length, bool includeValue)
    {
        byte[] payload = new byte[prefix.PaddedLength];
        try
        {
            if (!this.TryDecrypt(key, PayloadNonce, header[SaltLength..], body[..prefix.PaddedLength],
                                 body[prefix.PaddedLength..], payload))
                return new(ReadStatus.Corrupt, length);

            string id = Utf8.GetString(payload.AsSpan(0, prefix.IdLength));
            byte[]? value = includeValue && !prefix.Deleted
                ? payload.AsSpan(prefix.IdLength, prefix.ContentLength - prefix.IdLength).ToArray()
                : null;
            return new(ReadStatus.Valid, length, id, prefix.Deleted, value);
        }
        catch (DecoderFallbackException)
        {
            return new(ReadStatus.Corrupt, length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    /// <summary>Normalizes AEAD authentication failures across providers.</summary>
    private bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                            ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {
        try
        {
            return this.aead.Decrypt(key, nonce, aad, ciphertext, tag, plaintext);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    #endregion

    internal enum ReadStatus { Valid, Truncated, Corrupt }

    internal readonly record struct RecordRead(ReadStatus Status, int Length = 0, string? Id = null,
                                               bool Deleted = false, byte[]? Value = null);

    private readonly record struct RecordPrefix(bool Deleted, int IdLength, int ContentLength, int PaddedLength);
}
