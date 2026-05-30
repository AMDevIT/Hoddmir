using Hoddmir.Core.Encryption.AEAD;
using Hoddmir.Core.Keys;
using Hoddmir.Keys;
using Hoddmir.Memory;
using Microsoft.Extensions.Logging;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Hoddmir.Storage;

/// <summary>
/// Append-only, encrypted key-value store.
/// <para>
/// Use the fluent builder to open or create a store:
/// <code>
/// var store = await EncryptedEntryStore.Configure()
///     .WithPassword(passwordBytes)
///     .WithArgon2id(paramsProvider)
///     .WithAead(new ChaCha20Poly1305Provider())
///     .OpenAsync(storeProvider, replacer, cancellationToken);
/// </code>
/// </para>
/// </summary>
///
/// <remarks>
/// File format v0x03 (all integers little-endian unless stated otherwise):
/// <code>
/// [MAGIC(4)="EES1"][VER(1)=0x03][KeyMode(1)][AeadId(1)][HeaderLen(4)][ModePayload][NoncePrefix(8)]
/// </code>
/// Record layout:
/// <code>
///  byte   Op       (0=Put, 1=Delete)
///  int64  Seq      (little-endian)
///  int32  KeyLen
///  int32  CtLen
///  12B    Nonce    = NoncePrefix(8) || Seq_BE(4)
///  KeyLen Key      (UTF-8)
///  CtLen  Ct
///  16B    Tag
/// </code>
/// AAD = Op(1) || Seq(8,LE) || KeyLen(4,LE) || CtLen(4,LE)
/// </remarks>
public sealed class EncryptedEntryStore : IAsyncDisposable
{
    #region Format constants

    private const uint MagicNumber = 0x31455345; // "EES1"
    private const byte Version = 0x03;        // 0x02→0x03: AeadId added to fixed header
    private const int FixedHeaderSize = 4 + 1 + 1 + 1 + 4; // MAGIC+VER+KeyMode+AeadId+HeaderLen
    private const int GCMNonceLen = 12;
    private const int GCMTagLen = 16;
    private const int NoncePrefixLen = 8;
    private const int RecordFixedPrefixLen = 1 + 8 + 4 + 4; // Op+Seq+KeyLen+CtLen
    private const int DefaultMemBufDim = 512;
    private const int DefaultPbkdf2Iters = 600_000;

    #endregion

    #region Fields

    private readonly IAppendOnlyStoreProvider _store;
    private readonly IAtomicReplace _replacer;
    private readonly IAEADProvider _aead;
    // Not readonly: RotateDekAsync replaces these in-place after a successful key rotation.
    private SensitiveBytes _dek;
    private SensitiveBytes _noncePrefix;

    private long _nextSeq;
    private readonly ConcurrentDictionary<string, IndexEntry> _index = new(StringComparer.Ordinal);
    private readonly ILogger? _logger;

    private record struct IndexEntry(long Seq, long Offset, int TotalLen, bool Deleted);

    #endregion

    #region Constructor (private — use builder)

    private EncryptedEntryStore(IAppendOnlyStoreProvider store,
                                IAtomicReplace replacer,
                                IAEADProvider aead,
                                byte[] dek,
                                byte[] noncePrefix,
                                long nextSeq,
                                ILogger? logger)
    {
        _store = store;
        _replacer = replacer;
        _aead = aead;
        _dek = new SensitiveBytes(32);
        _noncePrefix = new SensitiveBytes(NoncePrefixLen);
        _logger = logger;
        _nextSeq = nextSeq;

        dek.AsSpan().CopyTo(_dek.AsSpan());
        noncePrefix.AsSpan().CopyTo(_noncePrefix.AsSpan());

        CryptographicOperations.ZeroMemory(dek);
        CryptographicOperations.ZeroMemory(noncePrefix);
    }

    #endregion

    #region Builder

    /// <summary>Returns a new <see cref="StoreBuilder"/> to configure and open a store.</summary>
    public static StoreBuilder Configure() => new();

    /// <summary>Fluent builder for <see cref="EncryptedEntryStore"/>.</summary>
    public sealed class StoreBuilder
    {
        private byte[]? _password;
        private KeyProtectionMode _mode = KeyProtectionMode.PasswordArgon2id;
        private IAEADProvider? _aead;
        private IArgon2idParamsProvider? _argonParams;
        private IArgonKeyProvider? _argonKeyProvider;
        private ILogger? _logger;

        /// <summary>Sets the password (raw UTF-8 bytes, not a string) and selects Argon2id protection.</summary>
        public StoreBuilder WithPassword(byte[] passwordUtf8,
                                         KeyProtectionMode mode = KeyProtectionMode.PasswordArgon2id)
        {
            _password = passwordUtf8;
            _mode = mode;
            return this;
        }

        /// <summary>Overrides the Argon2id parameter provider (default: <see cref="CalibratingArgon2idParamsProvider"/>).</summary>
        public StoreBuilder WithArgon2id(IArgon2idParamsProvider provider) { _argonParams = provider; return this; }

        /// <summary>Overrides the Argon2id key derivation implementation.</summary>
        public StoreBuilder WithArgonKeyProvider(IArgonKeyProvider provider) { _argonKeyProvider = provider; return this; }

        /// <summary>Sets the AEAD provider used to encrypt individual records.</summary>
        public StoreBuilder WithAead(IAEADProvider provider) { _aead = provider; return this; }

        /// <summary>Attaches a logger.</summary>
        public StoreBuilder WithLogger(ILogger logger) { _logger = logger; return this; }

        /// <summary>Opens or creates the store using the configured options.</summary>
        public Task<EncryptedEntryStore> OpenAsync(IAppendOnlyStoreProvider store,
                                                   IAtomicReplace replacer,
                                                   CancellationToken ct = default)
        {
            if (_aead is null)
                throw new InvalidOperationException("An AEAD provider must be set via WithAead().");

            return EncryptedEntryStore.OpenCoreAsync(
                store, replacer, _aead, _mode,
                _password ?? [],
                _argonParams,
                _argonKeyProvider,
                _logger, ct);
        }
    }

    #endregion

    #region Public API

    /// <summary>Encrypts <paramref name="value"/> and appends it as a Put record.</summary>
    public async Task PutAsync(string id,
                               ReadOnlyMemory<byte> value,
                               CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(id))
            throw new ArgumentException("Entry ID must not be empty.", nameof(id));

        byte[] keyBytes = Encoding.UTF8.GetBytes(id);
        long seq = Interlocked.Increment(ref _nextSeq);
        byte[] nonce = BuildNonce(seq);
        const byte op = 0;

        Span<byte> aad = BuildAad(op, seq, keyBytes.Length, value.Length);

        byte[] ct_buf = new byte[value.Length];
        byte[] tag = new byte[GCMTagLen];

        _aead.Encrypt(_dek.AsSpan(), nonce, aad, value.Span, ct_buf, tag);

        int total = RecordFixedPrefixLen + GCMNonceLen + keyBytes.Length + ct_buf.Length + GCMTagLen;
        byte[] buf = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            SerializeRecord(buf, op, seq, nonce, keyBytes, ct_buf, tag);
            long offset = await _store.GetLengthAsync(ct).ConfigureAwait(false);
            await _store.AppendAsync(buf.AsMemory(0, total), ct).ConfigureAwait(false);
            await _store.FlushAsync(true, ct).ConfigureAwait(false);
            _index[id] = new IndexEntry(seq, offset, total, Deleted: false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
            CryptographicOperations.ZeroMemory(ct_buf);
        }
    }

    /// <summary>Decrypts and returns the value for <paramref name="id"/>, or <c>null</c> if not found or deleted.</summary>
    public async Task<byte[]?> GetAsync(string id, CancellationToken ct = default)
    {
        if (!_index.TryGetValue(id, out var idx) || idx.Deleted)
            return null;

        byte[] rented = ArrayPool<byte>.Shared.Rent(idx.TotalLen);
        try
        {
            var seg = new ArraySegment<byte>(rented, 0, idx.TotalLen);
            int read = await _store.ReadAtAsync(idx.Offset, seg, ct).ConfigureAwait(false);
            if (read != idx.TotalLen) return null;

            if (!TryParseRecord(seg, out byte op, out long seq, out int keyLen, out int ctLen,
                                out byte[] nonce, out byte[] keyBytes, out byte[] ctBuf, out byte[] tag))
                return null;

            if (op != 0) return null;
            if (!string.Equals(Encoding.UTF8.GetString(keyBytes), id, StringComparison.Ordinal)) return null;

            Span<byte> aad = BuildAad(op, seq, keyLen, ctLen);
            byte[] pt = new byte[ctLen];
            try
            {
                if (!_aead.Decrypt(_dek.AsSpan(), nonce, aad, ctBuf, tag, pt))
                    return null;
                CryptographicOperations.ZeroMemory(aad);
                return pt;
            }
            catch (CryptographicException)
            {
                return null;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>Appends a Delete (tombstone) record for <paramref name="id"/>.</summary>
    public async Task DeleteAsync(string id, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(id)) return;

        byte[] keyBytes = Encoding.UTF8.GetBytes(id);
        long seq = Interlocked.Increment(ref _nextSeq);
        byte[] nonce = BuildNonce(seq);
        const byte op = 1;

        Span<byte> aad = BuildAad(op, seq, keyBytes.Length, 0);
        byte[] tag = new byte[GCMTagLen];

        _aead.Encrypt(_dek.AsSpan(), nonce, aad, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag);
        CryptographicOperations.ZeroMemory(aad);

        int total = RecordFixedPrefixLen + GCMNonceLen + keyBytes.Length + GCMTagLen;
        byte[] buf = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            SerializeRecord(buf, op, seq, nonce, keyBytes, [], tag);
            long offset = await _store.GetLengthAsync(ct).ConfigureAwait(false);
            await _store.AppendAsync(buf.AsMemory(0, total), ct).ConfigureAwait(false);
            await _store.FlushAsync(true, ct).ConfigureAwait(false);
            _index[id] = new IndexEntry(seq, offset, total, Deleted: true);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    /// <summary>Returns all live (non-deleted) entry IDs.</summary>
    public IReadOnlyCollection<string> ListIds() =>
        [.. _index.Where(kv => !kv.Value.Deleted).Select(kv => kv.Key)];

    /// <summary>
    /// Rewrites the store keeping only live entries, renewing their nonces and sequence numbers.
    /// Reduces file size by discarding tombstones and superseded versions.
    /// </summary>
    public async Task CompactAsync(CancellationToken ct = default)
    {
        await _replacer.ReplaceWithAsync(async stream =>
        {
            // 1. Copy header unchanged
            await CopyHeaderAsync(_store, stream, ct).ConfigureAwait(false);

            // 2. Re-encrypt live records with fresh nonces
            long newSeq = 0;
            foreach (string id in _index.Where(kv => !kv.Value.Deleted).Select(kv => kv.Key))
            {
                byte[]? pt = await GetAsync(id, ct).ConfigureAwait(false);
                if (pt is null) continue;

                byte[] keyBytes = Encoding.UTF8.GetBytes(id);
                long seq = Interlocked.Increment(ref newSeq);
                byte[] nonce = BuildNonce(seq);
                const byte op = 0;

                byte[] ctBuf = new byte[pt.Length];
                byte[] tag = new byte[_aead.TagSizeBytes];

                Span<byte> aad = BuildAad(op, seq, keyBytes.Length, ctBuf.Length);

                byte[] tmpDek = _dek.ToManagedCopy();
                try
                {
                    _aead.Encrypt(tmpDek, nonce, aad, pt, ctBuf, tag);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(tmpDek);
                    CryptographicOperations.ZeroMemory(aad);
                }

                int total = RecordFixedPrefixLen + nonce.Length + keyBytes.Length + ctBuf.Length + tag.Length;
                byte[] recBuf = new byte[total];
                SerializeRecord(recBuf, op, seq, nonce, keyBytes, ctBuf, tag);
                await stream.WriteAsync(recBuf, 0, total, ct).ConfigureAwait(false);
            }

            await stream.FlushAsync(ct).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);

        // 3. Rebuild in-memory index
        byte[] dekCopy = _dek.ToManagedCopy();
        try
        {
            _index.Clear();
            _nextSeq = await RebuildIndexAsync(_store, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Error rebuilding index after compaction.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dekCopy);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _dek.Dispose();
        _noncePrefix.Dispose();
        await _store.FlushAsync(true).ConfigureAwait(false);
    }

    /// <summary>
    /// Rotates the Data Encryption Key (DEK): generates a new random DEK and nonce prefix,
    /// re-encrypts all live records, and rewrites the store header with the new DEK
    /// wrapped under the new (or unchanged) password and protection mode.
    /// <para>
    /// The current password is always required to authenticate the caller before rotation.
    /// If <paramref name="newPasswordUtf8"/> is <c>null</c>, the same password is reused
    /// for the new header. If <paramref name="newMode"/> is <c>null</c>, the same
    /// <see cref="KeyProtectionMode"/> as the current store is reused.
    /// </para>
    /// <para>
    /// The operation is atomic: the backing store is only replaced after the entire new
    /// file has been written successfully. On failure, the store remains readable with
    /// the old DEK.
    /// </para>
    /// <para>
    /// For <see cref="KeyProtectionMode.WindowsDPAPI"/>, <paramref name="currentPasswordUtf8"/>
    /// and <paramref name="newPasswordUtf8"/> are ignored — DPAPI uses the OS account identity.
    /// </para>
    /// </summary>
    /// <param name="currentPasswordUtf8">
    /// The current password (raw UTF-8 bytes). Required to authenticate the rotation request.
    /// </param>
    /// <param name="newPasswordUtf8">
    /// The new password. If <c>null</c>, the current password is reused.
    /// </param>
    /// <param name="newMode">
    /// The new key protection mode. If <c>null</c>, the current mode is reused.
    /// </param>
    /// <param name="newArgonParams">
    /// Argon2id parameters for the new header. If <c>null</c> and the new mode is
    /// <see cref="KeyProtectionMode.PasswordArgon2id"/>, a fresh calibration is run.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416",
        Justification = "DPAPI path is guarded by OperatingSystem.IsWindows()")]
    public async Task RotateDekAsync(
        byte[] currentPasswordUtf8,
        byte[]? newPasswordUtf8 = null,
        KeyProtectionMode? newMode = null,
        IArgon2idParamsProvider? newArgonParams = null,
        CancellationToken ct = default)
    {
        // Read the current mode from the on-disk header so we can validate the
        // current password and know which mode to inherit if newMode is null.
        KeyProtectionMode currentMode = await ReadModeFromHeaderAsync(_store, ct)
                                             .ConfigureAwait(false);

        // Authenticate caller: verify they know the current password before rotating.
        // DPAPI: skip password check — OS identity is the implicit authenticator.
        if (currentMode != KeyProtectionMode.WindowsDPAPI)
        {
            if (currentPasswordUtf8 is null || currentPasswordUtf8.Length == 0)
                throw new ArgumentException(
                    "Current password is required to authenticate the key rotation.", nameof(currentPasswordUtf8));

            // Re-derive the current DEK from the on-disk header using the supplied password.
            // If the password is wrong, ReadHeaderAsync will fail to authenticate the AEAD tag
            // and return garbage — we detect this by comparing with the live DEK.
            (byte[] candidateDek, byte[] _) = await ReadHeaderAsync(
                _store, _aead, currentMode, currentPasswordUtf8, new ArgonKeyProvider(), ct)
                .ConfigureAwait(false);

            bool dekMatches = CryptographicOperations.FixedTimeEquals(
                candidateDek.AsSpan(), _dek.AsSpan());

            CryptographicOperations.ZeroMemory(candidateDek);

            if (!dekMatches)
                throw new CryptographicException(
                    "Current password is incorrect. Key rotation aborted.");
        }

        KeyProtectionMode targetMode = newMode ?? currentMode;
        byte[] targetPassword = newPasswordUtf8 ?? currentPasswordUtf8 ?? [];

        // Generate fresh DEK and NoncePrefix.
        byte[] newDek = MemoryBlockHelper.RandomBytes(32);
        byte[] newNoncePrefix = MemoryBlockHelper.RandomBytes(NoncePrefixLen);

        // Atomically rewrite the entire store with the new key material.
        await RewriteWithNewKeyAsync(newDek, newNoncePrefix, targetMode,
                                     targetPassword, newArgonParams, ct)
             .ConfigureAwait(false);

        // Swap in-memory key material only after the file has been safely written.
        SensitiveBytes oldDek = _dek;
        SensitiveBytes oldNoncePrefix = _noncePrefix;

        var freshDek = new SensitiveBytes(32);
        var freshPrefix = new SensitiveBytes(NoncePrefixLen);
        newDek.AsSpan().CopyTo(freshDek.AsSpan());
        newNoncePrefix.AsSpan().CopyTo(freshPrefix.AsSpan());

        _dek = freshDek;
        _noncePrefix = freshPrefix;

        // Zero and dispose old key material.
        oldDek.Dispose();
        oldNoncePrefix.Dispose();
        CryptographicOperations.ZeroMemory(newDek);
        CryptographicOperations.ZeroMemory(newNoncePrefix);

        // Rebuild index from the newly written store.
        _index.Clear();
        _nextSeq = await RebuildIndexAsync(_store, ct).ConfigureAwait(false);

        _logger?.LogDebug("DEK rotation completed successfully.");
    }

    #endregion

    #region Internal helpers

    // Builds a 12-byte nonce: NoncePrefix(8) || seq(4, big-endian).
    private byte[] BuildNonce(long seq)
    {
        byte[] n = new byte[GCMNonceLen];
        _noncePrefix.AsSpan().CopyTo(n.AsSpan(0, NoncePrefixLen));
        BinaryPrimitives.WriteUInt32BigEndian(n.AsSpan(NoncePrefixLen, 4), (uint)seq);
        return n;
    }

    // Overload used during RewriteWithNewKeyAsync, before _noncePrefix is swapped.
    private static byte[] BuildNonce(byte[] noncePrefix, long seq)
    {
        byte[] n = new byte[GCMNonceLen];
        noncePrefix.AsSpan(0, NoncePrefixLen).CopyTo(n.AsSpan(0, NoncePrefixLen));
        BinaryPrimitives.WriteUInt32BigEndian(n.AsSpan(NoncePrefixLen, 4), (uint)seq);
        return n;
    }

    // Rewrites the entire store atomically using a new DEK and nonce prefix.
    // Used by both RotateDekAsync and (in future) any operation that needs a full rekey.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416",
        Justification = "DPAPI path is guarded by OperatingSystem.IsWindows()")]
    private async Task RewriteWithNewKeyAsync(
        byte[] newDek,
        byte[] newNoncePrefix,
        KeyProtectionMode mode,
        byte[] passwordUtf8,
        IArgon2idParamsProvider? argonParams,
        CancellationToken ct)
    {
        // Snapshot the live plaintext values of all entries before touching the file.
        // We must read them now while the old DEK is still active.
        var liveIds = _index.Where(kv => !kv.Value.Deleted)
                            .Select(kv => kv.Key)
                            .ToArray();

        var snapshots = new List<(string Id, byte[] Plaintext)>(liveIds.Length);
        foreach (string id in liveIds)
        {
            byte[]? pt = await GetAsync(id, ct).ConfigureAwait(false);
            if (pt is not null)
                snapshots.Add((id, pt));
        }

        await _replacer.ReplaceWithAsync(async stream =>
        {
            // 1. Write new header with new DEK and new NoncePrefix
            using var ms = new MemoryStream(DefaultMemBufDim);
            WriteHeader(ms, newDek, newNoncePrefix, mode, _aead, passwordUtf8,
                        argonParams, new ArgonKeyProvider());
            byte[] hdrBytes = ms.ToArray();
            await stream.WriteAsync(hdrBytes, ct).ConfigureAwait(false);

            // 2. Re-encrypt all live records with the new DEK and new nonces
            long newSeq = 0;
            foreach (var (id, pt) in snapshots)
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(id);
                long seq = Interlocked.Increment(ref newSeq);
                byte[] nonce = BuildNonce(newNoncePrefix, seq);
                const byte op = 0;

                byte[] ctBuf = new byte[pt.Length];
                byte[] tag = new byte[_aead.TagSizeBytes];
                byte[] aad = BuildAad(op, seq, keyBytes.Length, ctBuf.Length);

                try
                {
                    _aead.Encrypt(newDek, nonce, aad, pt, ctBuf, tag);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(aad);
                }

                int total = RecordFixedPrefixLen + nonce.Length + keyBytes.Length + ctBuf.Length + tag.Length;
                byte[] recBuf = new byte[total];
                SerializeRecord(recBuf, op, seq, nonce, keyBytes, ctBuf, tag);
                await stream.WriteAsync(recBuf, 0, total, ct).ConfigureAwait(false);
            }

            await stream.FlushAsync(ct).ConfigureAwait(false);

        }, ct).ConfigureAwait(false);

        // Zero plaintext snapshots now that the file has been written.
        foreach (var (_, pt) in snapshots)
            CryptographicOperations.ZeroMemory(pt);
    }

    // Reads only the KeyProtectionMode byte from the on-disk fixed header.
    private static async Task<KeyProtectionMode> ReadModeFromHeaderAsync(
        IAppendOnlyStoreProvider store, CancellationToken ct)
    {
        byte[] hdr = new byte[FixedHeaderSize];
        int got = await store.ReadAtAsync(0, hdr, ct).ConfigureAwait(false);
        if (got != FixedHeaderSize) throw new InvalidDataException("Incomplete fixed header.");

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(hdr);
        if (magic != MagicNumber) throw new InvalidDataException("Wrong magic number.");

        byte ver = hdr[4];
        if (ver != Version)
            throw new NotSupportedException($"Store version {ver} is not supported (expected {Version}).");

        return (KeyProtectionMode)hdr[5];
    }

    // AAD = Op(1) || Seq(8,LE) || KeyLen(4,LE) || CtLen(4,LE) — 17 bytes total.
    private static byte[] BuildAad(byte op, long seq, int keyLen, int ctLen)
    {
        byte[] aad = new byte[17];
        aad[0] = op;
        BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan(1, 8), seq);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(9, 4), keyLen);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(13, 4), ctLen);
        return aad;
    }

    private static void SerializeRecord(byte[] buf, byte op, long seq,
                                        byte[] nonce, byte[] keyBytes, byte[] ct, byte[] tag)
    {
        int off = 0;
        buf[off++] = op;
        BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(off, 8), seq); off += 8;
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(off, 4), keyBytes.Length); off += 4;
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(off, 4), ct.Length); off += 4;
        nonce.CopyTo(buf.AsSpan(off, nonce.Length)); off += nonce.Length;
        keyBytes.CopyTo(buf.AsSpan(off, keyBytes.Length)); off += keyBytes.Length;
        ct.CopyTo(buf.AsSpan(off, ct.Length)); off += ct.Length;
        tag.CopyTo(buf.AsSpan(off, tag.Length));
    }

    private bool TryParseRecord(ArraySegment<byte> seg,
                                 out byte op, out long seq, out int keyLen, out int ctLen,
                                 out byte[] nonce, out byte[] keyBytes, out byte[] ctBuf, out byte[] tag)
    {
        op = 0; seq = 0; keyLen = 0; ctLen = 0;
        nonce = []; keyBytes = []; ctBuf = []; tag = [];

        if (seg.Count < RecordFixedPrefixLen) return false;

        int off = seg.Offset;
        op = seg.Array![off++];
        seq = BinaryPrimitives.ReadInt64LittleEndian(seg.Array.AsSpan(off, 8)); off += 8;
        keyLen = BinaryPrimitives.ReadInt32LittleEndian(seg.Array.AsSpan(off, 4)); off += 4;
        ctLen = BinaryPrimitives.ReadInt32LittleEndian(seg.Array.AsSpan(off, 4)); off += 4;

        int nonceLen = _aead.NonceSizeBytes;
        int tagLen = _aead.TagSizeBytes;

        if (seg.Count < RecordFixedPrefixLen + nonceLen + keyLen + ctLen + tagLen) return false;

        nonce = seg.Array.AsSpan(off, nonceLen).ToArray(); off += nonceLen;
        keyBytes = seg.Array.AsSpan(off, keyLen).ToArray(); off += keyLen;
        ctBuf = seg.Array.AsSpan(off, ctLen).ToArray(); off += ctLen;
        tag = seg.Array.AsSpan(off, tagLen).ToArray();
        return true;
    }

    private async Task<long> RebuildIndexAsync(IAppendOnlyStoreProvider store, CancellationToken ct)
    {
        long pos = await HeaderEndOffsetAsync(store, ct).ConfigureAwait(false);
        long fileLen = await store.GetLengthAsync(ct).ConfigureAwait(false);

        var newIndex = new Dictionary<string, IndexEntry>(StringComparer.Ordinal);
        long maxSeq = 0;

        byte[] prefix = new byte[RecordFixedPrefixLen];
        int nonceLen = _aead.NonceSizeBytes;
        int tagLen = _aead.TagSizeBytes;

        while (pos < fileLen)
        {
            int got = await store.ReadAtAsync(pos, prefix, ct).ConfigureAwait(false);
            if (got == 0) break;
            if (got != prefix.Length) throw new InvalidDataException("Truncated record (prefix).");

            byte op = prefix[0];
            long seq = BinaryPrimitives.ReadInt64LittleEndian(prefix.AsSpan(1, 8));
            int keyLen = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(9, 4));
            int ctLen = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(13, 4));

            int restLen = nonceLen + keyLen + ctLen + tagLen;
            if (restLen < 0) throw new InvalidDataException("Record length overflow.");

            byte[] rest = new byte[restLen];
            got = await store.ReadAtAsync(pos + prefix.Length, rest, ct).ConfigureAwait(false);
            if (got != restLen) throw new InvalidDataException("Truncated record (body).");

            // Extract key (no decryption needed)
            int keyOff = nonceLen;
            string id = Encoding.UTF8.GetString(rest, keyOff, keyLen);
            int total = prefix.Length + restLen;

            newIndex[id] = new IndexEntry(seq, pos, total, Deleted: op == 1);
            if (seq > maxSeq) maxSeq = seq;
            pos += total;
        }

        _index.Clear();
        foreach (var kv in newIndex)
            _index[kv.Key] = kv.Value;

        return maxSeq;
    }

    private static async Task<long> HeaderEndOffsetAsync(IAppendOnlyStoreProvider store, CancellationToken ct)
    {
        byte[] hdr = new byte[FixedHeaderSize];
        int got = await store.ReadAtAsync(0, hdr, ct).ConfigureAwait(false);
        if (got != FixedHeaderSize) throw new InvalidDataException("Incomplete fixed header.");

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(hdr);
        if (magic != MagicNumber) throw new InvalidDataException("Wrong magic number (not an EES store).");

        byte ver = hdr[4];
        if (ver != Version)
            throw new NotSupportedException($"Store version {ver} is not supported (expected {Version}).");

        int headerLen = BinaryPrimitives.ReadInt32LittleEndian(hdr.AsSpan(FixedHeaderSize - 4, 4));
        return FixedHeaderSize + headerLen;
    }

    private static async Task CopyHeaderAsync(IAppendOnlyStoreProvider store, Stream dest, CancellationToken ct)
    {
        byte[] fixedPart = new byte[FixedHeaderSize];
        int got = await store.ReadAtAsync(0, fixedPart, ct).ConfigureAwait(false);
        if (got != FixedHeaderSize) throw new InvalidDataException("Incomplete fixed header.");

        int headerLen = BinaryPrimitives.ReadInt32LittleEndian(fixedPart.AsSpan(FixedHeaderSize - 4, 4));
        byte[] payload = new byte[headerLen];
        got = await store.ReadAtAsync(FixedHeaderSize, payload, ct).ConfigureAwait(false);
        if (got != headerLen) throw new InvalidDataException("Incomplete header payload.");

        await dest.WriteAsync(fixedPart, ct).ConfigureAwait(false);
        await dest.WriteAsync(payload, ct).ConfigureAwait(false);
    }

    #endregion

    #region OpenCoreAsync (called by builder)

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416",
        Justification = "DPAPI path is guarded by OperatingSystem.IsWindows()")]
    internal static async Task<EncryptedEntryStore> OpenCoreAsync(
        IAppendOnlyStoreProvider store,
        IAtomicReplace replacer,
        IAEADProvider aead,
        KeyProtectionMode mode,
        byte[] passwordUtf8,
        IArgon2idParamsProvider? argonParamsProvider,
        IArgonKeyProvider? argonKeyProvider,
        ILogger? logger,
        CancellationToken ct)
    {
        argonKeyProvider ??= new ArgonKeyProvider();

        long len = await store.GetLengthAsync(ct).ConfigureAwait(false);

        if (len == 0)
        {
            byte[] dek = MemoryBlockHelper.RandomBytes(32);
            byte[] noncePrefix = MemoryBlockHelper.RandomBytes(NoncePrefixLen);

            using var ms = new MemoryStream(DefaultMemBufDim);
            WriteHeader(ms, dek, noncePrefix, mode, aead, passwordUtf8, argonParamsProvider, argonKeyProvider);

            await store.AppendAsync(ms.ToArray(), ct).ConfigureAwait(false);
            await store.FlushAsync(true, ct).ConfigureAwait(false);

            return new EncryptedEntryStore(store, replacer, aead, dek, noncePrefix, nextSeq: 0, logger);
        }
        else
        {
            (byte[] dek, byte[] noncePrefix) = await ReadHeaderAsync(store, aead, mode, passwordUtf8,
                                                                     argonKeyProvider, ct)
                                                    .ConfigureAwait(false);

            var instance = new EncryptedEntryStore(store, replacer, aead, dek, noncePrefix, 0, logger);

            long nextSeq = await instance.RebuildIndexAsync(store, ct).ConfigureAwait(false);
            instance._nextSeq = nextSeq;

            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(noncePrefix);

            return instance;
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416",
        Justification = "DPAPI path is guarded by OperatingSystem.IsWindows()")]
    private static void WriteHeader(Stream dest,
                                    byte[] dek,
                                    byte[] noncePrefix,
                                    KeyProtectionMode mode,
                                    IAEADProvider aead,
                                    ReadOnlySpan<byte> passwordUtf8,
                                    IArgon2idParamsProvider? argonParamsProvider,
                                    IArgonKeyProvider argonKeyProvider)
    {
        byte[] modePayload = BuildModePayload(mode, dek, aead, passwordUtf8,
                                              argonParamsProvider, argonKeyProvider);

        // Fixed header: MAGIC(4) VER(1) KeyMode(1) AeadId(1) HeaderLen(4)
        // where HeaderLen = modePayload.Length + NoncePrefixLen
        int totalPayload = modePayload.Length + NoncePrefixLen;

        using var bw = new BinaryWriter(dest, Encoding.UTF8, leaveOpen: true);
        bw.Write(MagicNumber);
        bw.Write(Version);
        bw.Write((byte)mode);
        bw.Write(GetAeadId(aead));
        bw.Write(totalPayload);
        bw.Write(modePayload);
        bw.Write(noncePrefix);
    }

    private static byte GetAeadId(IAEADProvider aead) => aead switch
    {
        AesCtrHmacSha256Provider => (byte)AeadAlgorithmId.AesCtrHmacSha256,
        AesGcmProvider => (byte)AeadAlgorithmId.AesGcm,
        _ => GetAeadIdByName(aead.Name),
    };

    private static byte GetAeadIdByName(string name) => name switch
    {
        "AES-GCM" => (byte)AeadAlgorithmId.AesGcm,
        "ChaCha20-Poly1305" => (byte)AeadAlgorithmId.ChaCha20Poly1305,
        "AES-CTR+HMAC-SHA256 (EtM)" => (byte)AeadAlgorithmId.AesCtrHmacSha256,
        _ => throw new NotSupportedException(
                 $"Cannot determine AeadAlgorithmId for provider '{name}'. " +
                 $"Override GetAeadId() or use a known provider.")
    };

    private static byte[] BuildModePayload(KeyProtectionMode mode,
                                           byte[] dek,
                                           IAEADProvider aead,
                                           ReadOnlySpan<byte> passwordUtf8,
                                           IArgon2idParamsProvider? argonParamsProvider,
                                           IArgonKeyProvider argonKeyProvider)
    {
        switch (mode)
        {
            case KeyProtectionMode.PasswordArgon2id:
                {
                    if (passwordUtf8.IsEmpty)
                        throw new ArgumentException("Password is required for Argon2id mode.");

                    var argonProvider = argonParamsProvider ?? new CalibratingArgon2idParamsProvider();
                    Argon2idParams p = argonProvider.GetParameters();
                    byte[] salt = MemoryBlockHelper.RandomBytes(16);
                    byte[] pwdTmp = passwordUtf8.ToArray();
                    byte[] kek = argonKeyProvider.DeriveKey(pwdTmp, salt, p);
                    CryptographicOperations.ZeroMemory(pwdTmp);

                    byte[] nonce = MemoryBlockHelper.RandomBytes(GCMNonceLen);
                    byte[] encDek = new byte[dek.Length];
                    byte[] tag = new byte[GCMTagLen];
                    aead.Encrypt(kek, nonce, ReadOnlySpan<byte>.Empty, dek, encDek, tag);
                    CryptographicOperations.ZeroMemory(kek);

                    // Layout: SaltLen(2) Salt MemKiB(4) Iters(4) Par(4) Nonce(12) EncDek(32) Tag(16)
                    var payload = new byte[2 + salt.Length + 4 + 4 + 4 + GCMNonceLen + encDek.Length + GCMTagLen];
                    var span = payload.AsSpan();
                    BinaryPrimitives.WriteUInt16LittleEndian(span, (ushort)salt.Length); span = span[2..];
                    salt.CopyTo(span); span = span[salt.Length..];
                    BinaryPrimitives.WriteInt32LittleEndian(span, p.MemoryKiB); span = span[4..];
                    BinaryPrimitives.WriteInt32LittleEndian(span, p.Iterations); span = span[4..];
                    BinaryPrimitives.WriteInt32LittleEndian(span, p.Parallelism); span = span[4..];
                    nonce.CopyTo(span); span = span[GCMNonceLen..];
                    encDek.CopyTo(span); span = span[encDek.Length..];
                    tag.CopyTo(span);

                    return payload;
                }

            case KeyProtectionMode.WindowsDPAPI:
                {
                    if (!OperatingSystem.IsWindows())
                        throw new PlatformNotSupportedException("Windows DPAPI is not available on this platform.");

                    return ProtectedData.Protect(dek, null, DataProtectionScope.CurrentUser);
                }

            case KeyProtectionMode.PasswordPBKDF2:
                {
                    if (passwordUtf8.IsEmpty)
                        throw new ArgumentException("Password is required for PBKDF2 mode.");

                    byte[] salt = MemoryBlockHelper.RandomBytes(16);
                    int iters = DefaultPbkdf2Iters;
                    // using var kdf = new Rfc2898DeriveBytes(passwordUtf8.ToArray(), salt, iters, HashAlgorithmName.SHA256);
                    byte[] kek = Rfc2898DeriveBytes.Pbkdf2(passwordUtf8, salt, iters, HashAlgorithmName.SHA256, 32);
                    byte[] nonce = MemoryBlockHelper.RandomBytes(GCMNonceLen);
                    byte[] encDek = new byte[dek.Length];
                    byte[] tag = new byte[GCMTagLen];

                    aead.Encrypt(kek, nonce, ReadOnlySpan<byte>.Empty, dek, encDek, tag);
                    CryptographicOperations.ZeroMemory(kek);

                    // Layout: SaltLen(2) Salt Iters(4) Nonce(12) EncDek(32) Tag(16)
                    byte[] payload = new byte[2 + salt.Length + 4 + GCMNonceLen + encDek.Length + GCMTagLen];
                    Span<byte> span = payload.AsSpan();
                    BinaryPrimitives.WriteUInt16LittleEndian(span, (ushort)salt.Length); span = span[2..];
                    salt.CopyTo(span); span = span[salt.Length..];
                    BinaryPrimitives.WriteInt32LittleEndian(span, iters); span = span[4..];
                    nonce.CopyTo(span); span = span[GCMNonceLen..];
                    encDek.CopyTo(span); span = span[encDek.Length..];
                    tag.CopyTo(span);

                    return payload;
                }

            default:
                throw new NotSupportedException($"Protection mode {mode} is not supported.");
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416",
        Justification = "DPAPI path is guarded by OperatingSystem.IsWindows()")]
    private static async Task<(byte[] Dek, byte[] NoncePrefix)> ReadHeaderAsync(
        IAppendOnlyStoreProvider store,
        IAEADProvider aead,
        KeyProtectionMode expectedMode,
        byte[] passwordUtf8,
        IArgonKeyProvider argonKeyProvider,
        CancellationToken ct)
    {
        byte[] fixedHdr = new byte[FixedHeaderSize];
        int got = await store.ReadAtAsync(0, fixedHdr, ct).ConfigureAwait(false);
        if (got != FixedHeaderSize) throw new InvalidDataException("Incomplete fixed header.");

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(fixedHdr);
        if (magic != MagicNumber) throw new InvalidDataException("Wrong magic number (not an EES store).");

        byte ver = fixedHdr[4];
        if (ver != Version)
            throw new NotSupportedException($"Store version {ver} is not supported (expected {Version}).");

        var modeOnDisk = (KeyProtectionMode)fixedHdr[5];
        var aeadIdOnDisk = (AeadAlgorithmId)fixedHdr[6];
        byte expectedId = GetAeadId(aead);

        if ((byte)aeadIdOnDisk != expectedId)
            throw new InvalidOperationException(
                $"Store was created with AEAD algorithm '{aeadIdOnDisk}' " +
                $"but the provided provider is '{aead.Name}' ({(AeadAlgorithmId)expectedId}). " +
                $"Use the matching provider.");

        int totalHeaderLen = BinaryPrimitives.ReadInt32LittleEndian(fixedHdr.AsSpan(FixedHeaderSize - 4, 4));
        if (totalHeaderLen < NoncePrefixLen)
            throw new InvalidDataException("Header too short to contain nonce prefix.");

        byte[] fullPayload = new byte[totalHeaderLen];
        got = await store.ReadAtAsync(FixedHeaderSize, fullPayload, ct).ConfigureAwait(false);
        if (got != fullPayload.Length) throw new InvalidDataException("Incomplete header payload.");

        int modePayloadLen = totalHeaderLen - NoncePrefixLen;
        byte[] modePayload = fullPayload[..modePayloadLen];
        byte[] noncePrefix = fullPayload[modePayloadLen..];

        byte[] dek = modeOnDisk switch
        {
            KeyProtectionMode.PasswordArgon2id => DecryptDekArgon2id(modePayload, aead, passwordUtf8, argonKeyProvider),
            KeyProtectionMode.WindowsDPAPI => DecryptDekDpapi(modePayload),
            KeyProtectionMode.PasswordPBKDF2 => DecryptDekPbkdf2(modePayload, aead, passwordUtf8),
            _ => throw new NotSupportedException($"Protection mode {modeOnDisk} is not supported.")
        };

        return (dek, noncePrefix);
    }

    private static byte[] DecryptDekArgon2id(byte[] payload, IAEADProvider aead,
                                             byte[] passwordUtf8, IArgonKeyProvider kp)
    {
        if (passwordUtf8.Length == 0)
            throw new ArgumentException("Password required for Argon2id.");

        ArraySegment<byte> span = new ArraySegment<byte>(payload);

        ushort saltLen = BinaryPrimitives.ReadUInt16LittleEndian(span);
        span = span[2..];

        byte[] salt = [.. span[..saltLen]];
        span = span[saltLen..];

        int memKiB = BinaryPrimitives.ReadInt32LittleEndian(span);
        span = span[4..];

        int iters = BinaryPrimitives.ReadInt32LittleEndian(span);
        span = span[4..];

        int par = BinaryPrimitives.ReadInt32LittleEndian(span);
        span = span[4..];

        byte[] nonce = [.. span[..GCMNonceLen]];
        span = span[GCMNonceLen..];

        int encDekLen = span.Count - GCMTagLen;
        byte[] encDek = [.. span[..encDekLen]];
        byte[] tag = [.. span[encDekLen..]];

        Argon2idParams p = new(memKiB, iters, par);
        byte[] pwdTmp = [.. passwordUtf8];
        byte[] kek = kp.DeriveKey(pwdTmp, salt, p);
        CryptographicOperations.ZeroMemory(pwdTmp);

        byte[] dek = new byte[encDek.Length];
        bool dekValid;

        try
        {
            dekValid = aead.Decrypt(kek, nonce, [], encDek, tag, dek);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }

        if (!dekValid)
        {
            CryptographicOperations.ZeroMemory(dek);
            throw new CryptographicException("Failed to decrypt the store DEK. The password is incorrect or the header is corrupted.");
        }

        return dek;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability",
                                                     "CA1416",
                                                     Justification = "Guarded by OperatingSystem.IsWindows()")]
    private static byte[] DecryptDekDpapi(byte[] payload)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows DPAPI is not available on this platform.");

        return ProtectedData.Unprotect(payload, null, DataProtectionScope.CurrentUser);
    }

    private static byte[] DecryptDekPbkdf2(byte[] payload, IAEADProvider aead, byte[] passwordUtf8)
    {
        if (passwordUtf8.Length == 0)
            throw new ArgumentException("Password required for PBKDF2.");

        ArraySegment<byte> span = new(payload);

        ushort saltLen = BinaryPrimitives.ReadUInt16LittleEndian(span);
        span = span[2..];

        byte[] salt = [.. span[..saltLen]];
        span = span[saltLen..];

        int iters = BinaryPrimitives.ReadInt32LittleEndian(span);
        span = span[4..];

        byte[] nonce = [.. span[..GCMNonceLen]];
        span = span[GCMNonceLen..];

        int encDekLen = span.Count - GCMTagLen;
        byte[] encDek = [.. span[..encDekLen]];
        byte[] tag = [.. span[encDekLen..]];

        // using Rfc2898DeriveBytes kdf = new ([.. passwordUtf8], salt, iters, HashAlgorithmName.SHA256);
        byte[] kek = Rfc2898DeriveBytes.Pbkdf2(passwordUtf8, salt, iters, HashAlgorithmName.SHA256, 32);
        byte[] dek = new byte[encDek.Length];
        bool validDek;

        try
        {
            validDek = aead.Decrypt(kek, nonce, ReadOnlySpan<byte>.Empty, encDek, tag, dek);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }

        if (!validDek)
        {
            CryptographicOperations.ZeroMemory(dek);
            throw new CryptographicException("Failed to decrypt the store DEK. The password is incorrect or the header is corrupted.");
        }

        return dek;
    }

    #endregion
}
