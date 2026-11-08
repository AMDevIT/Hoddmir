using Hoddmir.Core.Encryption.AEAD;
using Hoddmir.Core.Keys;
using Hoddmir.Memory;
using Microsoft.Extensions.Logging;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Hoddmir.Storage;

/// <summary>An append-only encrypted key-value store with an in-memory index.</summary>
public sealed class EncryptedEntryStore : IAsyncDisposable
{
    #region Const

    private const uint InternalMagic = 0x31455345; // EES1, visible only after decryption.
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

    #endregion

    #region Fields

    private readonly IAppendOnlyStoreProvider store;
    private readonly IAtomicReplace replacer;
    private readonly IAEADProvider aead;
    private readonly IArgonKeyProvider argonKeyProvider;
    private readonly EncryptedRecordCodec codec;
    private readonly ILogger? logger;
    private readonly SemaphoreSlim gate = new(1, 1);

    private SensitiveBytes dek;
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
                                IArgonKeyProvider argonKeyProvider, SensitiveBytes dek, int sessionSaltLength,
                                int sessionIterations, ILogger? logger)
    {
        this.store = store;
        this.replacer = replacer;
        this.aead = aead;
        this.argonKeyProvider = argonKeyProvider;
        this.codec = new(aead);
        this.dek = dek;
        this.sessionSaltLength = sessionSaltLength;
        this.sessionIterations = sessionIterations;
        this.logger = logger;
        this.endOffset = sessionSaltLength + EncryptedHeaderSize;
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

    /// <summary>Returns the current value or null if it is absent or cannot be read.</summary>
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

    /// <summary>Atomically rewrites the active records and removes any incomplete tail.</summary>
    public async Task CompactAsync(CancellationToken ct = default)
    {
        await this.gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            this.EnsureUsable();
            byte[] header = new byte[this.sessionSaltLength + EncryptedHeaderSize];
            if (!await EncryptedRecordCodec.ReadExactlyAsync(this.store, 0, header, ct).ConfigureAwait(false))
                throw new InvalidDataException("Incomplete store header.");

            await this.RewriteAsync(header, this.dek, ct).ConfigureAwait(false);
        }
        finally { this.gate.Release(); }
    }

    /// <summary>Authenticates the records and reports corruption or truncation.</summary>
    public async Task<VerifyResult> VerifyAsync(CancellationToken ct = default)
    {
        await this.gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            this.EnsureUsable();
            return await this.ScanAsync(rebuildIndex: false, ct).ConfigureAwait(false);
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

            using SensitiveBytes currentDek = await ReadHeaderAsync(this.store, this.aead, this.argonKeyProvider,
                                                                    currentPasswordUtf8, this.sessionIterations,
                                                                    this.sessionSaltLength, ct).ConfigureAwait(false);
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
            await this.store.FlushAsync(true).ConfigureAwait(false);
        }
        finally { this.gate.Release(); }
    }

    /// <summary>Creates or opens a store and authenticates the log before exposing its index.</summary>
    private static async Task<EncryptedEntryStore> OpenCoreAsync(IAppendOnlyStoreProvider store, IAtomicReplace replacer,
                                                                 IAEADProvider aead, byte[] passwordUtf8, int sessionIterations,
                                                                 int sessionSaltLength, IArgon2idParamsProvider? dekArgonParams,
                                                                 IArgonKeyProvider argonKeyProvider, ILogger? logger,
                                                                 CancellationToken ct)
    {
        if (aead.KeySizeBytes != DekLength || aead.NonceSizeBytes != NonceLength || aead.TagSizeBytes != TagLength)
            throw new NotSupportedException("The store requires a 32-byte key, 12-byte nonce and 16-byte tag.");

        bool create = await store.GetLengthAsync(ct).ConfigureAwait(false) == 0;
        SensitiveBytes dek = create
            ? CreateDek()
            : await ReadHeaderAsync(store, aead, argonKeyProvider, passwordUtf8,
                                    sessionIterations, sessionSaltLength, ct).ConfigureAwait(false);

        try
        {
            EncryptedEntryStore instance = new(store, replacer, aead, argonKeyProvider, dek,
                                               sessionSaltLength, sessionIterations, logger);
            if (create)
            {
                byte[] header = await CreateHeaderAsync(aead, argonKeyProvider, dek, passwordUtf8, sessionIterations,
                                                        sessionSaltLength, dekArgonParams, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                long offset = await store.AppendAsync(header).ConfigureAwait(false);
                if (offset != 0)
                    throw new IOException("Store initialization did not start at offset zero.");
                await store.FlushAsync(true).ConfigureAwait(false);
            }
            else
            {
                VerifyResult result = await instance.ScanAsync(rebuildIndex: true, ct).ConfigureAwait(false);
                instance.incompleteTail = result.TruncatedRecords != 0;
            }

            return instance;
        }
        catch
        {
            dek.Dispose();
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
            byte[] record = this.codec.Encode(this.dek, expectedOffset, id, value.Span, deleted);
            ct.ThrowIfCancellationRequested();

            try
            {
                long offset = await this.store.AppendAsync(record).ConfigureAwait(false);
                if (offset != expectedOffset)
                    throw new IOException("The backend appended at an unexpected offset.");

                await this.store.FlushAsync(true).ConfigureAwait(false);
                this.UpdateIndex(id, deleted, offset, record.Length);
                this.endOffset = offset + record.Length;
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
    private async Task<byte[]?> ReadValueAsync(string id, IndexEntry entry, CancellationToken ct)
    {
        EncryptedRecordCodec.RecordRead record = await this.codec.ReadAsync(this.store, this.dek, entry.Offset,
                                                                            entry.Offset + entry.Length,
                                                                            includeValue: true, ct).ConfigureAwait(false);
        if (record.Status == EncryptedRecordCodec.ReadStatus.Valid &&
            record.Length == entry.Length && StringComparer.Ordinal.Equals(record.Id, id))
            return record.Value;

        if (record.Value is not null)
            CryptographicOperations.ZeroMemory(record.Value);

        return null;
    }

    /// <summary>Walks authenticated records in file order and optionally rebuilds the active index.</summary>
    private async Task<VerifyResult> ScanAsync(bool rebuildIndex, CancellationToken ct)
    {
        long position = this.sessionSaltLength + EncryptedHeaderSize;
        long length = await this.store.GetLengthAsync(ct).ConfigureAwait(false);
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
                                                                                length, includeValue: false, ct)
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
                this.logger?.LogWarning("Record '{Key}' at offset 0x{Offset:x} failed verification.", label, position);
                if (record.Length == 0)
                    break;
            }
            else
            {
                if (rebuildIndex)
                    this.UpdateIndex(record.Id!, record.Deleted, position, record.Length);

                valid++;
            }

            position += record.Length;
        }

        if (rebuildIndex)
            this.endOffset = position;

        return new(total, valid, corrupt.Count, truncated.Count, corrupt.AsReadOnly(), truncated.AsReadOnly());
    }

    /// <summary>Stages a new file and index and publishes both after successful replacement.</summary>
    private async Task RewriteAsync(byte[] header, SensitiveBytes targetDek, CancellationToken ct)
    {
        Dictionary<string, IndexEntry> newIndex = new(StringComparer.Ordinal);
        long offset = header.Length;
        bool staged = false;
        try
        {
            await this.replacer.ReplaceWithAsync(async stream =>
            {
                await stream.WriteAsync(header, ct).ConfigureAwait(false);
                foreach ((string id, IndexEntry entry) in this.index)
                {
                    byte[]? value = await this.ReadValueAsync(id, entry, ct).ConfigureAwait(false);
                    if (value is null)
                        throw new InvalidDataException($"Active record at offset 0x{entry.Offset:x} is unreadable.");

                    try
                    {
                        byte[] record = this.codec.Encode(targetDek, offset, id, value, deleted: false);
                        await stream.WriteAsync(record, ct).ConfigureAwait(false);
                        newIndex.Add(id, new(offset, record.Length));
                        offset += record.Length;
                    }
                    finally { CryptographicOperations.ZeroMemory(value); }
                }

                staged = true;
            },
                                                 ct).ConfigureAwait(false);
        }
        catch (Exception error) when (staged && error is not OperationCanceledException)
        {
            this.writeFaulted = true;
            throw;
        }

        this.index = newIndex;
        this.endOffset = offset;
        this.incompleteTail = false;
    }

    /// <summary>Applies an authenticated mutation to the in-memory index.</summary>
    private void UpdateIndex(string id, bool deleted, long offset, int length)
    {
        if (deleted)
            this.index.Remove(id);
        else
            this.index[id] = new(offset, length);
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
                aead.Encrypt(dekKek, plaintext.AsSpan(DekNonceOffset, NonceLength), ReadOnlySpan<byte>.Empty,
                             dek.AsSpan(), plaintext.AsSpan(WrappedDekOffset, DekLength),
                             plaintext.AsSpan(DekTagOffset, TagLength));
            }
            finally { CryptographicOperations.ZeroMemory(dekKek); }

            byte[] sessionKek = argonKeyProvider.DeriveKey(password, salt, new(SessionMemKiB, iterations, SessionParallelism));
            try
            {
                aead.Encrypt(sessionKek, salt[..NonceLength], ReadOnlySpan<byte>.Empty, plaintext,
                             header.AsSpan(saltLength, HeaderPlainLength), header.AsSpan(saltLength + HeaderPlainLength));
            }
            finally { CryptographicOperations.ZeroMemory(sessionKek); }

            return header;
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    /// <summary>Authenticates the header and unwraps its pinned data key.</summary>
    private static async Task<SensitiveBytes> ReadHeaderAsync(IAppendOnlyStoreProvider store, IAEADProvider aead,
                                                              IArgonKeyProvider argonKeyProvider, byte[] password,
                                                              int iterations, int saltLength, CancellationToken ct)
    {
        byte[] header = new byte[saltLength + EncryptedHeaderSize];
        if (!await EncryptedRecordCodec.ReadExactlyAsync(store, 0, header, ct).ConfigureAwait(false))
            throw new InvalidDataException("Incomplete header blob.");

        byte[] plaintext = new byte[HeaderPlainLength];
        ReadOnlySpan<byte> salt = header.AsSpan(0, saltLength);
        try
        {
            byte[] sessionKek = argonKeyProvider.DeriveKey(password, salt, new(SessionMemKiB, iterations, SessionParallelism));
            try
            {
                if (!aead.Decrypt(sessionKek, salt[..NonceLength], ReadOnlySpan<byte>.Empty,
                                  header.AsSpan(saltLength, HeaderPlainLength),
                                  header.AsSpan(saltLength + HeaderPlainLength), plaintext))
                    throw new CryptographicException("Failed to decrypt store header. Check the password, session parameters and AEAD.");
            }
            finally { CryptographicOperations.ZeroMemory(sessionKek); }

            if (BinaryPrimitives.ReadUInt32LittleEndian(plaintext) != InternalMagic)
                throw new InvalidDataException("Wrong internal magic. Not an EES store or data corrupted.");
            if (plaintext[4] != Version)
                throw new NotSupportedException($"Store version 0x{plaintext[4]:x2} not supported (expected 0x{Version:x2}).");
            if (plaintext[5] != GetAeadId(aead))
                throw new InvalidOperationException($"Store AEAD 0x{plaintext[5]:x2} does not match provider '{aead.Name}'.");

            Argon2idParams parameters = new(BinaryPrimitives.ReadInt32LittleEndian(plaintext.AsSpan(DekParametersOffset)),
                                            BinaryPrimitives.ReadInt32LittleEndian(plaintext.AsSpan(DekParametersOffset + 4)),
                                            BinaryPrimitives.ReadInt32LittleEndian(plaintext.AsSpan(DekParametersOffset + 8)));
            byte[] dekKek = argonKeyProvider.DeriveKey(password, plaintext.AsSpan(DekSaltOffset, DekSaltLength), parameters);
            try
            {
                SensitiveBytes dek = new(DekLength);
                try
                {
                    if (!aead.Decrypt(dekKek, plaintext.AsSpan(DekNonceOffset, NonceLength), ReadOnlySpan<byte>.Empty,
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

    /// <summary>Maps compatible implementations to the persisted algorithm ID.</summary>
    private static byte GetAeadId(IAEADProvider aead) => aead.Name switch
    {
        "AES-GCM" or "AES-GCM (BouncyCastle)" => (byte)AeadAlgorithmId.AesGcm,
        "ChaCha20-Poly1305" => (byte)AeadAlgorithmId.ChaCha20Poly1305,
        "AES-CTR+HMAC-SHA256 (EtM)" => (byte)AeadAlgorithmId.AesCtrHmacSha256,
        _ => throw new NotSupportedException($"Cannot determine AeadAlgorithmId for '{aead.Name}'.")
    };

    #endregion

    private readonly record struct IndexEntry(long Offset, int Length);

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
                                                   CancellationToken ct = default)
        {
            if (this.aead is null)
                throw new InvalidOperationException("An AEAD provider must be set via WithAead().");
            if (this.password is null || this.password.Length == 0)
                throw new InvalidOperationException("A password must be set via WithPassword().");

            return OpenCoreAsync(store, replacer, this.aead, this.password, this.sessionIterations, this.sessionSaltLength,
                                 this.dekArgonParams, this.argonKeyProvider ?? new ArgonKeyProvider(), this.logger, ct);
        }

        #endregion
    }
}
