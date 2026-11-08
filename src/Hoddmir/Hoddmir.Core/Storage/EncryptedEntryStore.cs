using Hoddmir.Core.Encryption.AEAD;
using Hoddmir.Core.Keys;
using Hoddmir.Memory;
using Microsoft.Extensions.Logging;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Hoddmir.Storage;

/// <summary>An append-only encrypted key-value store with an in-memory index.</summary>
public sealed class EncryptedEntryStore : IAsyncDisposable
{
    #region Const

    private const uint InternalMagic = 0x31534545; // EES1, visible only after decryption.
    private const byte Version = 0x01;
    private const int EncryptedHeaderSize = 512;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int DekLength = 32;
    private const int DekSaltLength = 16;
    private const int HeaderPlainLength = EncryptedHeaderSize - TagLength;
    private const int DekNonceOffset = sizeof(uint) + 2;
    private const int WrappedDekOffset = DekNonceOffset + NonceLength;
    private const int DekTagOffset = WrappedDekOffset + DekLength;
    private const int DekSaltOffset = DekTagOffset + TagLength;
    private const int DekParametersOffset = DekSaltOffset + DekSaltLength;
    private const int SessionMemKiB = 65_536;
    private const int SessionParallelism = 2;
    private const int DefaultSessionIterations = 2;
    private const int DefaultSessionSaltLength = 16;
    private const int MaxDekMemoryKiB = 512 * 1024;
    private const int MaxDekIterations = 10;
    private const int MaxDekParallelism = 16;

    #endregion

    #region Fields

    private static readonly ConditionalWeakTable<IAppendOnlyStoreProvider, SemaphoreSlim> BackendLeases = new();
    private readonly IAppendOnlyStoreProvider store;
    private readonly IAtomicReplace replacer;
    private readonly IAEADProvider aead;
    private readonly IArgonKeyProvider argonKeyProvider;
    private readonly EncryptedRecordCodec codec;
    private readonly ILogger? logger;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly SemaphoreSlim backendLease;

    private SensitiveBytes dek;
    private byte[] validatedHeader;
    private byte[] endDigest;
    private Dictionary<string, IndexEntry> index = new(StringComparer.Ordinal);
    private int sessionSaltLength;
    private int sessionIterations;
    private long endOffset;
    private bool incompleteTail;
    private bool writeFaulted;
    private bool disposed;

    #endregion

    #region .ctor

    private EncryptedEntryStore(IAppendOnlyStoreProvider store, IAtomicReplace replacer, IAEADProvider aead,
                                IArgonKeyProvider argonKeyProvider, SensitiveBytes dek, byte[] validatedHeader,
                                int sessionSaltLength, int sessionIterations, ILogger? logger,
                                SemaphoreSlim backendLease)
    {
        this.store = store;
        this.replacer = replacer;
        this.aead = aead;
        this.argonKeyProvider = argonKeyProvider;
        this.codec = new(aead);
        this.dek = dek;
        this.validatedHeader = validatedHeader;
        this.backendLease = backendLease;
        this.sessionSaltLength = sessionSaltLength;
        this.sessionIterations = sessionIterations;
        this.logger = logger;
        this.endOffset = validatedHeader.Length;
        this.endDigest = SHA256.HashData(validatedHeader);
    }

    #endregion

    #region Methods

    /// <summary>Starts configuring a new or existing store.</summary>
    public static StoreBuilder Configure() => new();

    /// <summary>Appends a new value for the specified ID.</summary>
    public Task PutAsync(string id, ReadOnlyMemory<byte> value, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        return this.AppendRecordAsync(id, value, deleted: false, ct);
    }

    /// <summary>Returns the current value or null if the ID is absent.</summary>
    /// <exception cref="InvalidDataException">The indexed record no longer matches the authenticated log.</exception>
    public async Task<byte[]?> GetAsync(string id, CancellationToken ct = default)
    {
        await this.gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            this.EnsureUsable();
            return this.index.TryGetValue(id, out IndexEntry entry)
                ? await this.ReadValueAsync(id, entry, ct).ConfigureAwait(false)
                : null;
        }
        finally { this.gate.Release(); }
    }

    /// <summary>Appends a tombstone for the specified ID.</summary>
    public Task DeleteAsync(string id, CancellationToken ct = default) =>
        string.IsNullOrEmpty(id) ? Task.CompletedTask : this.AppendRecordAsync(id, ReadOnlyMemory<byte>.Empty, deleted: true, ct);

    /// <summary>Returns a snapshot of the active IDs.</summary>
    public IReadOnlyCollection<string> ListIds()
    {
        this.gate.Wait();
        try
        {
            this.EnsureUsable();
            return this.index.Keys.ToArray();
        }
        finally { this.gate.Release(); }
    }

    /// <summary>Returns the committed log checkpoint for storage in a trusted location.</summary>
    public async Task<byte[]> GetCheckpointAsync(CancellationToken ct = default)
    {
        await this.gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            this.EnsureUsable();
            if (this.incompleteTail)
                throw new InvalidDataException("Recover the incomplete tail before obtaining a checkpoint.");
            return (byte[])this.endDigest.Clone();
        }
        finally { this.gate.Release(); }
    }

    /// <summary>Atomically rewrites the active records and removes any incomplete tail.</summary>
    public async Task CompactAsync(CancellationToken ct = default)
    {
        await this.gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            this.EnsureUsable();
            byte[]? header = await ReadHeaderBytesAsync(this.store, this.sessionSaltLength, ct).ConfigureAwait(false);
            if (header is null)
                throw new InvalidDataException("Incomplete store header.");
            if (!header.AsSpan().SequenceEqual(this.validatedHeader))
                throw new InvalidDataException("The store header changed after opening.");

            await this.ValidateRewriteSourceAsync(ct).ConfigureAwait(false);
            await this.RewriteAsync(this.validatedHeader, this.dek, ct).ConfigureAwait(false);
        }
        finally { this.gate.Release(); }
    }

    /// <summary>Checks the header and authenticates the records, reporting corruption or truncation.</summary>
    public async Task<VerifyResult> VerifyAsync(CancellationToken ct = default)
    {
        await this.gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            this.EnsureUsable();
            byte[]? header = await ReadHeaderBytesAsync(this.store, this.sessionSaltLength, ct).ConfigureAwait(false);
            if (header is null)
                return new(0, 0, 0, 1, [], [0L]);

            VerifyResult result = await this.ScanAsync(rebuildIndex: false, ct).ConfigureAwait(false);
            return result with { IsHeaderCorrupted = !header.AsSpan().SequenceEqual(this.validatedHeader) };
        }
        finally { this.gate.Release(); }
    }

    /// <summary>Authenticates the current password and atomically rewrites the store with a fresh data key.</summary>
    public async Task RotateDekAsync(byte[] currentPasswordUtf8,
                                     byte[]? newPasswordUtf8 = null,
                                     int? newSessionIters = null,
                                     int? newSessionSaltLen = null,
                                     IArgon2idParamsProvider? newDekArgonParams = null,
                                     CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(currentPasswordUtf8);
        ArgumentOutOfRangeException.ThrowIfZero(currentPasswordUtf8.Length);
        if (newPasswordUtf8 is not null)
            ArgumentOutOfRangeException.ThrowIfZero(newPasswordUtf8.Length);

        await this.gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            this.EnsureUsable();
            int targetIterations = newSessionIters ?? this.sessionIterations;
            int targetSaltLength = newSessionSaltLen ?? this.sessionSaltLength;
            ValidateSessionParameters(targetIterations, targetSaltLength);

            byte[] currentHeader = await ReadHeaderBytesAsync(this.store, this.sessionSaltLength, ct).ConfigureAwait(false)
                ?? throw new InvalidDataException("Incomplete store header.");
            if (!currentHeader.AsSpan().SequenceEqual(this.validatedHeader))
                throw new InvalidDataException("The store header changed after opening.");

            await this.ValidateRewriteSourceAsync(ct).ConfigureAwait(false);
            using SensitiveBytes currentDek = DecryptHeader(currentHeader, this.aead, this.argonKeyProvider,
                                                            currentPasswordUtf8, this.sessionIterations, this.sessionSaltLength);
            if (!CryptographicOperations.FixedTimeEquals(currentDek.AsSpan(), this.dek.AsSpan()))
                throw new CryptographicException("Current password is incorrect. Key rotation aborted.");

            SensitiveBytes newDek = CreateDek();
            try
            {
                byte[] header = await CreateHeaderAsync(this.aead, this.argonKeyProvider, newDek,
                                                        newPasswordUtf8 ?? currentPasswordUtf8, targetIterations,
                                                        targetSaltLength, newDekArgonParams, ct).ConfigureAwait(false);

                await this.RewriteAsync(header, newDek, ct).ConfigureAwait(false);
            }
            catch
            {
                newDek.Dispose();
                throw;
            }

            this.dek.Dispose();
            this.dek = newDek;
            this.sessionIterations = targetIterations;
            this.sessionSaltLength = targetSaltLength;
            this.logger?.LogDebug("DEK rotation completed.");
        }
        finally { this.gate.Release(); }
    }

    /// <summary>Clears the data key and flushes the backend.</summary>
    public async ValueTask DisposeAsync()
    {
        await this.gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (this.disposed)
                return;

            this.disposed = true;
            this.dek.Dispose();
            this.index.Clear();
            try { await this.store.FlushAsync(true).ConfigureAwait(false); }
            finally { this.backendLease.Release(); }
        }
        finally { this.gate.Release(); }
    }

    /// <summary>Creates or opens a store and authenticates the log before exposing its index.</summary>
    private static async Task<EncryptedEntryStore> OpenCoreAsync(IAppendOnlyStoreProvider store, IAtomicReplace replacer,
                                                                 IAEADProvider aead, byte[] passwordUtf8, int sessionIterations,
                                                                 int sessionSaltLength, IArgon2idParamsProvider? dekArgonParams,
                                                                 IArgonKeyProvider argonKeyProvider, ILogger? logger,
                                                                 bool? createNew, ReadOnlyMemory<byte> expectedCheckpoint,
                                                                 CancellationToken ct)
    {
        if (aead.KeySizeBytes != DekLength || aead.NonceSizeBytes != NonceLength || aead.TagSizeBytes != TagLength)
            throw new NotSupportedException("The store requires a 32-byte key, 12-byte nonce and 16-byte tag.");

        SemaphoreSlim backendLease = BackendLeases.GetValue(store, static _ => new(1, 1));
        if (!backendLease.Wait(0, ct))
            throw new InvalidOperationException("This backend is already attached to an open store.");

        SensitiveBytes? dek = null;
        try
        {
            bool create = await store.GetLengthAsync(ct).ConfigureAwait(false) == 0;
            if (createNew == false && create)
                throw new InvalidDataException("The existing store is empty or missing.");
            if (createNew == true && !create)
                throw new IOException("Cannot create a store on a nonempty backend.");

            byte[]? header = create
                ? null
                : (await ReadHeaderBytesAsync(store, sessionSaltLength, ct).ConfigureAwait(false)
                   ?? throw new InvalidDataException("Incomplete header blob."));
            dek = header is null
                ? CreateDek()
                : DecryptHeader(header, aead, argonKeyProvider, passwordUtf8, sessionIterations, sessionSaltLength);

            if (header is null)
            {
                header = await CreateHeaderAsync(aead, argonKeyProvider, dek, passwordUtf8, sessionIterations,
                                                 sessionSaltLength, dekArgonParams, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                long offset = await store.AppendAsync(header).ConfigureAwait(false);
                if (offset != 0)
                    throw new IOException("Store initialization did not start at offset zero.");
                await store.FlushAsync(true).ConfigureAwait(false);
            }

            EncryptedEntryStore instance = new(store, replacer, aead, argonKeyProvider, dek, header,
                                               sessionSaltLength, sessionIterations, logger, backendLease);
            if (!create)
            {
                VerifyResult result = await instance.ScanAsync(rebuildIndex: true, ct).ConfigureAwait(false);
                instance.incompleteTail = result.TruncatedRecords != 0;
                if (!expectedCheckpoint.IsEmpty &&
                    !CryptographicOperations.FixedTimeEquals(expectedCheckpoint.Span, instance.endDigest))
                    throw new InvalidDataException("The store does not match the trusted log checkpoint.");
            }

            return instance;
        }
        catch
        {
            dek?.Dispose();
            backendLease.Release();
            throw;
        }
    }

    /// <summary>Writes one complete mutation and publishes its index update after the flush.</summary>
    private async Task AppendRecordAsync(string id, ReadOnlyMemory<byte> value, bool deleted, CancellationToken ct)
    {
        await this.gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            this.EnsureUsable();
            if (this.incompleteTail)
                throw new InvalidDataException("Compact the store to remove its incomplete tail before appending.");

            long expectedOffset = this.endOffset;
            byte[] record = this.codec.Encode(this.dek, expectedOffset, this.endDigest, id, value.Span, deleted);
            byte[] digest = SHA256.HashData(record);
            ct.ThrowIfCancellationRequested();

            try
            {
                if (await this.store.GetLengthAsync().ConfigureAwait(false) != expectedOffset)
                    throw new IOException("The backend length changed before append.");
                long offset = await this.store.AppendAsync(record).ConfigureAwait(false);
                if (offset != expectedOffset)
                    throw new IOException("The backend appended at an unexpected offset.");

                await this.store.FlushAsync(true).ConfigureAwait(false);
                this.UpdateIndex(id, deleted, new(offset, record.Length, this.endDigest, digest));
                this.endOffset = offset + record.Length;
                this.endDigest = digest;
            }
            catch
            {
                this.writeFaulted = true;
                throw;
            }
        }
        finally { this.gate.Release(); }
    }

    /// <summary>Reads the indexed record with the same authenticated codec used by the scanner.</summary>
    private async Task<byte[]> ReadValueAsync(string id, IndexEntry entry, CancellationToken ct)
    {
        EncryptedRecordCodec.RecordRead record = await this.codec.ReadAsync(this.store, this.dek, entry.Offset,
                                                                            entry.Offset + entry.Length,
                                                                            entry.PreviousDigest,
                                                                            includeValue: true, ct).ConfigureAwait(false);
        if (record.Status == EncryptedRecordCodec.ReadStatus.Valid &&
            record.Length == entry.Length && record.Digest.AsSpan().SequenceEqual(entry.Digest) &&
            StringComparer.Ordinal.Equals(record.Id, id) && !record.Deleted)
            return record.Value!;

        if (record.Value is not null)
            CryptographicOperations.ZeroMemory(record.Value);

        throw new InvalidDataException($"Indexed record at offset 0x{entry.Offset:x} changed or failed authentication.");
    }

    /// <summary>Walks authenticated records in file order and optionally rebuilds the active index.</summary>
    private async Task<VerifyResult> ScanAsync(bool rebuildIndex, CancellationToken ct)
    {
        long position = this.validatedHeader.Length;
        long length = await this.store.GetLengthAsync(ct).ConfigureAwait(false);
        byte[] digest = SHA256.HashData(this.validatedHeader);
        int total = 0;
        int valid = 0;
        List<string> corrupt = [];
        List<long> truncated = [];

        if (length < position)
            truncated.Add(0);

        while (position < length)
        {
            ct.ThrowIfCancellationRequested();
            EncryptedRecordCodec.RecordRead record = await this.codec.ReadAsync(this.store, this.dek, position,
                                                                                length, digest,
                                                                                includeValue: false, ct)
                                                                     .ConfigureAwait(false);

            if (record.Status == EncryptedRecordCodec.ReadStatus.Truncated)
            {
                truncated.Add(position);
                break;
            }

            total++;
            if (record.Status == EncryptedRecordCodec.ReadStatus.Corrupt)
            {
                if (rebuildIndex)
                    throw new InvalidDataException($"Record at offset 0x{position:x} failed authentication or validation.");

                string label = this.index.FirstOrDefault(entry => entry.Value.Offset == position).Key ??
                               $"<unknown@0x{position:x}>";
                corrupt.Add(label);
                this.logger?.LogWarning("Record at offset 0x{Offset:x} failed verification.", position);
                break;
            }
            else
            {
                if (rebuildIndex)
                    this.UpdateIndex(record.Id!, record.Deleted, new(position, record.Length, digest, record.Digest!));

                digest = record.Digest!;
                valid++;
            }

            position += record.Length;
        }

        if (rebuildIndex)
        {
            this.endOffset = position;
            this.endDigest = digest;
        }

        return new(total, valid, corrupt.Count, truncated.Count, corrupt.AsReadOnly(), truncated.AsReadOnly())
        {
            IsLogChanged = !rebuildIndex && corrupt.Count == 0 &&
                           (position != this.endOffset || !digest.AsSpan().SequenceEqual(this.endDigest))
        };
    }

    /// <summary>Rejects rewrites of changed committed data while allowing recovery from an incomplete tail.</summary>
    private async Task ValidateRewriteSourceAsync(CancellationToken ct)
    {
        VerifyResult result = await this.ScanAsync(rebuildIndex: false, ct).ConfigureAwait(false);
        if (result.CorruptedRecords != 0 || result.IsLogChanged)
            throw new InvalidDataException("The committed store log is corrupt or has changed after opening.");
    }

    /// <summary>Stages a new file and index and publishes both after successful replacement.</summary>
    private async Task RewriteAsync(byte[] header, SensitiveBytes targetDek, CancellationToken ct)
    {
        Dictionary<string, IndexEntry> newIndex = new(StringComparer.Ordinal);
        long offset = header.Length;
        byte[] digest = SHA256.HashData(header);
        bool staged = false;
        try
        {
            await this.replacer.ReplaceWithAsync(async stream =>
            {
                await stream.WriteAsync(header, ct).ConfigureAwait(false);
                foreach ((string id, IndexEntry entry) in this.index)
                {
                    byte[] value = await this.ReadValueAsync(id, entry, ct).ConfigureAwait(false);

                    try
                    {
                        byte[] record = this.codec.Encode(targetDek, offset, digest, id, value, deleted: false);
                        await stream.WriteAsync(record, ct).ConfigureAwait(false);
                        byte[] previousDigest = digest;
                        digest = SHA256.HashData(record);
                        newIndex.Add(id, new(offset, record.Length, previousDigest, digest));
                        offset += record.Length;
                    }
                    finally { CryptographicOperations.ZeroMemory(value); }
                }

                staged = true;
            },
                                                 ct).ConfigureAwait(false);
        }
        catch when (staged)
        {
            this.writeFaulted = true;
            throw;
        }

        this.index = newIndex;
        this.validatedHeader = header;
        this.endOffset = offset;
        this.endDigest = digest;
        this.incompleteTail = false;
    }

    /// <summary>Applies an authenticated mutation to the in-memory index.</summary>
    private void UpdateIndex(string id, bool deleted, IndexEntry entry)
    {
        if (deleted)
            this.index.Remove(id);
        else
            this.index[id] = entry;
    }

    /// <summary>Prevents use of a disposed store or one whose last write has an uncertain outcome.</summary>
    private void EnsureUsable()
    {
        ObjectDisposedException.ThrowIf(this.disposed, this);
        if (this.writeFaulted)
            throw new InvalidOperationException("Reopen the store after the failed write to recover its index.");
    }

    /// <summary>Generates a fresh data key in a pinned buffer.</summary>
    private static SensitiveBytes CreateDek()
    {
        SensitiveBytes key = new(DekLength);
        RandomNumberGenerator.Fill(key.AsSpan());
        return key;
    }

    /// <summary>Validates the externally supplied header parameters.</summary>
    private static void ValidateSessionParameters(int iterations, int saltLength)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(saltLength, DefaultSessionSaltLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(saltLength, 256);
    }

    /// <summary>Builds an encrypted header with separate session and data-key derivations.</summary>
    private static async Task<byte[]> CreateHeaderAsync(IAEADProvider aead, IArgonKeyProvider argonKeyProvider,
                                                        SensitiveBytes dek, byte[] password, int iterations, int saltLength,
                                                        IArgon2idParamsProvider? parameters, CancellationToken ct)
    {
        Argon2idParams dekParams = parameters is null
            ? new(131_072, 3, 4)
            : await parameters.GetParametersAsync(ct).ConfigureAwait(false);
        ValidateDekParameters(dekParams);
        ct.ThrowIfCancellationRequested();

        byte[] header = new byte[saltLength + EncryptedHeaderSize];
        byte[] plaintext = RandomNumberGenerator.GetBytes(HeaderPlainLength);
        Span<byte> salt = header.AsSpan(0, saltLength);
        Span<byte> dekSalt = plaintext.AsSpan(DekSaltOffset, DekSaltLength);
        RandomNumberGenerator.Fill(salt);

        try
        {
            BinaryPrimitives.WriteUInt32LittleEndian(plaintext, InternalMagic);
            plaintext[4] = Version;
            plaintext[5] = GetAeadId(aead);
            BinaryPrimitives.WriteInt32LittleEndian(plaintext.AsSpan(DekParametersOffset), dekParams.MemoryKiB);
            BinaryPrimitives.WriteInt32LittleEndian(plaintext.AsSpan(DekParametersOffset + 4), dekParams.Iterations);
            BinaryPrimitives.WriteInt32LittleEndian(plaintext.AsSpan(DekParametersOffset + 8), dekParams.Parallelism);

            byte[] dekKek = argonKeyProvider.DeriveKey(password, dekSalt, dekParams);
            try
            {
                aead.Encrypt(dekKek, plaintext.AsSpan(DekNonceOffset, NonceLength), "Hoddmir/0x01/dek"u8,
                             dek.AsSpan(), plaintext.AsSpan(WrappedDekOffset, DekLength),
                             plaintext.AsSpan(DekTagOffset, TagLength));
            }
            finally { CryptographicOperations.ZeroMemory(dekKek); }

            byte[] sessionKek = argonKeyProvider.DeriveKey(password, salt, new(SessionMemKiB, iterations, SessionParallelism));
            try
            {
                aead.Encrypt(sessionKek, salt[..NonceLength], "Hoddmir/0x01/header"u8, plaintext,
                             header.AsSpan(saltLength, HeaderPlainLength), header.AsSpan(saltLength + HeaderPlainLength));
            }
            finally { CryptographicOperations.ZeroMemory(sessionKek); }

            return header;
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    /// <summary>Reads the encrypted header or returns null if it is incomplete.</summary>
    private static async Task<byte[]?> ReadHeaderBytesAsync(IAppendOnlyStoreProvider store, int saltLength, CancellationToken ct)
    {
        byte[] header = new byte[saltLength + EncryptedHeaderSize];
        return await EncryptedRecordCodec.ReadExactlyAsync(store, 0, header, ct).ConfigureAwait(false)
            ? header
            : null;
    }

    /// <summary>Authenticates the encrypted header and unwraps its pinned data key.</summary>
    private static SensitiveBytes DecryptHeader(byte[] header, IAEADProvider aead, IArgonKeyProvider argonKeyProvider,
                                                byte[] password, int iterations, int saltLength)
    {
        byte[] plaintext = new byte[HeaderPlainLength];
        ReadOnlySpan<byte> salt = header.AsSpan(0, saltLength);
        try
        {
            byte[] sessionKek = argonKeyProvider.DeriveKey(password, salt, new(SessionMemKiB, iterations, SessionParallelism));
            try
            {
                if (!aead.Decrypt(sessionKek, salt[..NonceLength], "Hoddmir/0x01/header"u8,
                                  header.AsSpan(saltLength, HeaderPlainLength),
                                  header.AsSpan(saltLength + HeaderPlainLength), plaintext))
                    throw new CryptographicException("Failed to decrypt store header. Check the password, session parameters and AEAD.");
            }
            finally { CryptographicOperations.ZeroMemory(sessionKek); }

            if (BinaryPrimitives.ReadUInt32LittleEndian(plaintext) != InternalMagic)
                throw new InvalidDataException("Wrong internal magic. Not an EES store or data corrupted.");
            if (plaintext[4] != Version)
                throw new NotSupportedException($"Store version 0x{plaintext[4]:x2} is not supported.");
            if (plaintext[5] != GetAeadId(aead))
                throw new InvalidOperationException($"Store AEAD 0x{plaintext[5]:x2} does not match provider '{aead.Name}'.");

            Argon2idParams parameters = new(BinaryPrimitives.ReadInt32LittleEndian(plaintext.AsSpan(DekParametersOffset)),
                                            BinaryPrimitives.ReadInt32LittleEndian(plaintext.AsSpan(DekParametersOffset + 4)),
                                            BinaryPrimitives.ReadInt32LittleEndian(plaintext.AsSpan(DekParametersOffset + 8)));
            ValidateDekParameters(parameters);
            byte[] dekKek = argonKeyProvider.DeriveKey(password, plaintext.AsSpan(DekSaltOffset, DekSaltLength), parameters);
            try
            {
                SensitiveBytes dek = new(DekLength);
                try
                {
                    if (!aead.Decrypt(dekKek, plaintext.AsSpan(DekNonceOffset, NonceLength), "Hoddmir/0x01/dek"u8,
                                      plaintext.AsSpan(WrappedDekOffset, DekLength),
                                      plaintext.AsSpan(DekTagOffset, TagLength), dek.AsSpan()))
                        throw new CryptographicException("Failed to decrypt the store DEK.");

                    return dek;
                }
                catch
                {
                    dek.Dispose();
                    throw;
                }
            }
            finally { CryptographicOperations.ZeroMemory(dekKek); }
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    /// <summary>Bounds the work requested by an authenticated header before invoking Argon2id.</summary>
    private static void ValidateDekParameters(Argon2idParams parameters)
    {
        if (parameters.Parallelism is < 1 or > MaxDekParallelism ||
            parameters.Iterations is < 1 or > MaxDekIterations ||
            parameters.MemoryKiB < 8 * parameters.Parallelism || parameters.MemoryKiB > MaxDekMemoryKiB)
            throw new InvalidDataException("The store's DEK Argon2id parameters are outside the supported bounds.");
    }

    /// <summary>Maps compatible implementations to the persisted algorithm ID.</summary>
    private static byte GetAeadId(IAEADProvider aead) => aead.Name switch
    {
        "AES-GCM" or "AES-GCM (BouncyCastle)" => (byte)AeadAlgorithmId.AesGcm,
        "ChaCha20-Poly1305" => (byte)AeadAlgorithmId.ChaCha20Poly1305,
        "AES-CTR+HMAC-SHA256 (EtM)" => (byte)AeadAlgorithmId.AesCtrHmacSha256,
        _ => throw new NotSupportedException($"Cannot determine AeadAlgorithmId for '{aead.Name}'.")
    };

    #endregion

    private readonly record struct IndexEntry(long Offset, int Length, byte[] PreviousDigest, byte[] Digest);

    /// <summary>Configures the password, derivation parameters and AEAD for a store.</summary>
    public sealed class StoreBuilder
    {
        #region Fields

        private byte[]? password;
        private IAEADProvider? aead;
        private IArgon2idParamsProvider? dekArgonParams;
        private IArgonKeyProvider? argonKeyProvider;
        private ILogger? logger;
        private int sessionIterations = DefaultSessionIterations;
        private int sessionSaltLength = DefaultSessionSaltLength;

        #endregion

        #region Methods

        /// <summary>Sets the password as UTF-8 bytes.</summary>
        public StoreBuilder WithPassword(byte[] passwordUtf8)
        {
            this.password = passwordUtf8;
            return this;
        }

        /// <summary>Sets the Argon2id iteration count used to protect the header.</summary>
        public StoreBuilder WithSessionIterations(int iterations)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);
            this.sessionIterations = iterations;
            return this;
        }

        /// <summary>Sets the header salt length in bytes. The same length is required on reopen.</summary>
        public StoreBuilder WithSessionSaltLength(int length)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(length, DefaultSessionSaltLength);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, 256);
            this.sessionSaltLength = length;
            return this;
        }

        /// <summary>Overrides the Argon2id parameters used to wrap the data key.</summary>
        public StoreBuilder WithDekArgon2id(IArgon2idParamsProvider provider)
        {
            this.dekArgonParams = provider;
            return this;
        }

        /// <summary>Overrides the Argon2id implementation.</summary>
        public StoreBuilder WithArgonKeyProvider(IArgonKeyProvider provider)
        {
            this.argonKeyProvider = provider;
            return this;
        }

        /// <summary>Sets the AEAD provider used for the header and records.</summary>
        public StoreBuilder WithAead(IAEADProvider provider)
        {
            this.aead = provider;
            return this;
        }

        /// <summary>Sets the optional diagnostic logger.</summary>
        public StoreBuilder WithLogger(ILogger logger)
        {
            this.logger = logger;
            return this;
        }

        /// <summary>Creates or opens an encrypted store using the configured credentials.</summary>
        public Task<EncryptedEntryStore> OpenAsync(IAppendOnlyStoreProvider store, IAtomicReplace replacer,
                                                   CancellationToken ct = default) =>
            this.OpenWithModeAsync(store, replacer, createNew: null, default, ct);

        /// <summary>Opens an existing vault and rejects empty or missing content.</summary>
        public Task<EncryptedEntryStore> OpenExistingAsync(IAppendOnlyStoreProvider store, IAtomicReplace replacer,
                                                           CancellationToken ct = default) =>
            this.OpenWithModeAsync(store, replacer, createNew: false, default, ct);

        /// <summary>Opens a vault only if its last complete record matches a trusted checkpoint.</summary>
        public Task<EncryptedEntryStore> OpenAtCheckpointAsync(IAppendOnlyStoreProvider store, IAtomicReplace replacer,
                                                               ReadOnlyMemory<byte> expectedCheckpoint,
                                                               CancellationToken ct = default)
        {
            if (expectedCheckpoint.Length != EncryptedRecordCodec.DigestLength)
                throw new ArgumentException("A checkpoint must contain 32 bytes.", nameof(expectedCheckpoint));
            return this.OpenWithModeAsync(store, replacer, createNew: false, expectedCheckpoint.ToArray(), ct);
        }

        /// <summary>Initializes an empty backend and rejects existing content.</summary>
        public Task<EncryptedEntryStore> CreateAsync(IAppendOnlyStoreProvider store, IAtomicReplace replacer,
                                                      CancellationToken ct = default) =>
            this.OpenWithModeAsync(store, replacer, createNew: true, default, ct);

        /// <summary>Validates configuration and opens the backend using the requested mode.</summary>
        private Task<EncryptedEntryStore> OpenWithModeAsync(IAppendOnlyStoreProvider store, IAtomicReplace replacer,
                                                           bool? createNew, ReadOnlyMemory<byte> expectedCheckpoint,
                                                           CancellationToken ct)
        {
            if (this.aead is null)
                throw new InvalidOperationException("An AEAD provider must be set via WithAead().");
            if (this.password is null || this.password.Length == 0)
                throw new InvalidOperationException("A password must be set via WithPassword().");

            return OpenCoreAsync(store, replacer, this.aead, this.password, this.sessionIterations, this.sessionSaltLength,
                                 this.dekArgonParams, this.argonKeyProvider ?? new ArgonKeyProvider(), this.logger,
                                 createNew, expectedCheckpoint, ct);
        }

        #endregion
    }
}
