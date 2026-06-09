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
using System.Text.Json;

namespace Hoddmir.Storage;

/// <summary>
/// Append-only, encrypted key-value store.
/// <para>
/// Use the fluent builder to open or create a store:
/// <code>
/// var store = await EncryptedEntryStore.Configure()
///     .WithPassword(passwordBytes)
///     .WithAead(new ChaCha20Poly1305Provider())
///     .OpenAsync(storeProvider, replacer, cancellationToken);
/// </code>
/// </para>
/// </summary>
///
/// <remarks>
/// File format v0x04 — fully opaque, no plaintext structure visible.
///
/// On-disk layout:
/// <code>
/// [Salt(SessionSaltLen)]
/// [EncryptedHeaderBlob(EncryptedHeaderSize=512)]
/// [Record...]
/// </code>
///
/// EncryptedHeaderBlob = Encrypt(KEK_session, hdrNonce, paddedHeaderPlaintext) || tag
///   where hdrNonce = salt[0..12]
///   and   KEK_session = Argon2id(password, salt, SessionMemKiB, sessionIters, SessionParallelism)
///
/// Header plaintext (114 bytes, padded to EncryptedHeaderSize-GCMTagLen with random bytes):
/// <code>
/// Magic(4)="EES1" | Ver(1)=0x04 | AeadId(1)
/// NoncePrefix(4) | IndexToken(16)
/// DekNonce(12) | EncDek(32) | DekTag(16)
/// DekArgonSalt(16) | DekArgonMemKiB(4) | DekArgonIters(4) | DekArgonPar(4)
/// </code>
///
/// Record layout (all opaque from outside):
/// <code>
/// [EncPrefix(PrefixPlainLen+TagLen=45)]
/// [Token(16)]
/// [PaddedCt(PaddedCtLen)]
/// [PayloadTag(TagLen=16)]
/// </code>
///
/// EncPrefix plaintext (29 bytes):
/// <code>
/// PreNoise(4) | Op(1) | Seq(8,LE) | KeyLen(4,LE) | CtLen(4,LE) | PaddedCtLen(4,LE) | PostNoise(4)
/// </code>
///
/// PaddedCt plaintext = keyBytes(KeyLen) || value(CtLen-KeyLen) || random_padding(PaddedCtLen-CtLen)
///
/// Nonce for EncPrefix   = NoncePrefix(4) || Token[4..12]
/// Nonce for PaddedCt    = NoncePrefix(4) || Seq_BE(8)
/// AAD for PayloadTag    = EncPrefix bytes (encryptedPrefix + prefixTag, 45 bytes)
///
/// IndexToken = HMAC-SHA256(dek, "EES1_INDEX")[0..16]
/// Index record uses IndexToken as its Token — opaque without the DEK.
/// Index payload = JSON map of { tokenHex -> id }.
/// </remarks>
public sealed class EncryptedEntryStore : IAsyncDisposable
{
    #region Format constants

    private const uint InternalMagic = 0x31455345; // "EES1" — only visible post-decryption
    private const byte Version = 0x04;
    private const int EncryptedHeaderSize = 512;        // fixed opaque blob = ct + tag
    private const int GCMNonceLen = 12;
    private const int GCMTagLen = 16;
    private const int NoncePrefixLen = 4;
    private const int TokenLen = 16;
    private const int DekLen = 32;
    private const int DekArgonSaltLen = 16;

    // Header plaintext size (before padding)
    // Magic(4)+Ver(1)+AeadId(1)+NoncePrefix(4)+IndexToken(16)
    // +DekNonce(12)+EncDek(32)+DekTag(16)+DekArgonSalt(16)+MemKiB(4)+Iters(4)+Par(4) = 114
    private const int HeaderPlainMinLen = 4 + 1 + 1 + 4 + 16 + 12 + 32 + 16 + 16 + 4 + 4 + 4; // 114

    // Prefix plaintext: PreNoise(4)+Op(1)+Seq(8)+KeyLen(4)+CtLen(4)+PaddedCtLen(4)+PostNoise(4)
    private const int PrefixPlainLen = 4 + 1 + 8 + 4 + 4 + 4 + 4; // 29
    // EncPrefix on disk = ciphertext(29) + tag(16) = 45
    private const int EncPrefixTotalLen = PrefixPlainLen + GCMTagLen; // 45

    private const int MaxCtPadding = 64;
    private const int DefaultMemBufDim = 512;

    // Session KDF — hardcoded, never stored on disk
    private const int SessionMemKiB = 65_536; // 64 MiB
    private const int SessionParallelism = 2;
    private const int DefaultSessionIters = 2;

    // DEK KDF defaults — stored inside encrypted header
    private const int DefaultDekMemKiB = 131_072; // 128 MiB
    private const int DefaultDekIters = 3;
    private const int DefaultDekPar = 4;

    #endregion

    #region Fields

    private readonly IAppendOnlyStoreProvider _store;
    private readonly IAtomicReplace _replacer;
    private readonly IAEADProvider _aead;
    private int _sessionSaltLen;
    private int _sessionIters;

    private SensitiveBytes _dek;
    private SensitiveBytes _noncePrefix;
    private SensitiveBytes _indexToken;

    private long _nextSeq;
    private readonly ConcurrentDictionary<string, IndexEntry> _index
        = new(StringComparer.Ordinal);
    // token hex → user-visible id (in-memory only)
    private readonly ConcurrentDictionary<string, string> _tokenToId
        = new(StringComparer.Ordinal);

    private readonly ILogger? _logger;

    private record struct IndexEntry(long Seq, long Offset, int TotalLen, bool Deleted);

    #endregion

    #region Constructor

    private EncryptedEntryStore(
        IAppendOnlyStoreProvider store,
        IAtomicReplace replacer,
        IAEADProvider aead,
        byte[] dek,
        byte[] noncePrefix,
        byte[] indexToken,
        int sessionSaltLen,
        int sessionIters,
        long nextSeq,
        ILogger? logger)
    {
        _store = store;
        _replacer = replacer;
        _aead = aead;
        _sessionSaltLen = sessionSaltLen;
        _sessionIters = sessionIters;
        _logger = logger;
        _nextSeq = nextSeq;

        _dek = new SensitiveBytes(DekLen);
        _noncePrefix = new SensitiveBytes(NoncePrefixLen);
        _indexToken = new SensitiveBytes(TokenLen);

        dek.AsSpan().CopyTo(_dek.AsSpan());
        noncePrefix.AsSpan().CopyTo(_noncePrefix.AsSpan());
        indexToken.AsSpan().CopyTo(_indexToken.AsSpan());

        CryptographicOperations.ZeroMemory(dek);
        CryptographicOperations.ZeroMemory(noncePrefix);
        CryptographicOperations.ZeroMemory(indexToken);
    }

    #endregion

    #region Builder

    public static StoreBuilder Configure() => new();

    public sealed class StoreBuilder
    {
        private byte[]? _password;
        private IAEADProvider? _aead;
        private IArgon2idParamsProvider? _dekArgonParams;
        private IArgonKeyProvider? _argonKeyProvider;
        private ILogger? _logger;
        private int _sessionIters = DefaultSessionIters;
        private int _sessionSaltLen = 16;

        /// <summary>Sets the password (raw UTF-8 bytes).</summary>
        public StoreBuilder WithPassword(byte[] passwordUtf8)
        { _password = passwordUtf8; return this; }

        /// <summary>
        /// Argon2id iterations for the session KEK (protects the header).
        /// Memory and parallelism are hardcoded. Default: 2.
        /// </summary>
        public StoreBuilder WithSessionIterations(int iterations)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);
            _sessionIters = iterations;
            return this;
        }

        /// <summary>
        /// Length in bytes of the random salt prepended to the file.
        /// Range: 16–256. Default: 16.
        /// Together with password and session iterations this forms the full
        /// set of credentials required to open the store.
        /// </summary>
        public StoreBuilder WithSessionSaltLength(int length)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(length, 16);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, 256);
            _sessionSaltLen = length;
            return this;
        }

        /// <summary>Overrides Argon2id parameters used to protect the DEK.</summary>
        public StoreBuilder WithDekArgon2id(IArgon2idParamsProvider provider)
        { _dekArgonParams = provider; return this; }

        /// <summary>Overrides the Argon2id key derivation implementation.</summary>
        public StoreBuilder WithArgonKeyProvider(IArgonKeyProvider provider)
        { _argonKeyProvider = provider; return this; }

        /// <summary>Sets the AEAD provider used to encrypt records and the header.</summary>
        public StoreBuilder WithAead(IAEADProvider provider)
        { _aead = provider; return this; }

        public StoreBuilder WithLogger(ILogger logger)
        { _logger = logger; return this; }

        public Task<EncryptedEntryStore> OpenAsync(
            IAppendOnlyStoreProvider store,
            IAtomicReplace replacer,
            CancellationToken ct = default)
        {
            if (_aead is null)
                throw new InvalidOperationException("An AEAD provider must be set via WithAead().");
            if (_password is null || _password.Length == 0)
                throw new InvalidOperationException("A password must be set via WithPassword().");

            return EncryptedEntryStore.OpenCoreAsync(
                store, replacer, _aead, _password,
                _sessionIters, _sessionSaltLen,
                _dekArgonParams, _argonKeyProvider ?? new ArgonKeyProvider(),
                _logger, ct);
        }
    }

    #endregion

    #region Public API

    public async Task PutAsync(string id, ReadOnlyMemory<byte> value, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(id))
            throw new ArgumentException("Entry ID must not be empty.", nameof(id));

        byte[] keyBytes = Encoding.UTF8.GetBytes(id);
        long seq = Interlocked.Increment(ref _nextSeq);
        byte[] token = MemoryBlockHelper.RandomBytes(TokenLen);
        string tokenHex = Convert.ToHexString(token);

        (byte[] buf, int totalLen) = BuildRecord(0, seq, keyBytes, value.Span, token);
        try
        {
            long offset = await _store.GetLengthAsync(ct).ConfigureAwait(false);
            await _store.AppendAsync(buf.AsMemory(0, totalLen), ct).ConfigureAwait(false);
            await _store.FlushAsync(true, ct).ConfigureAwait(false);
            _index[id] = new IndexEntry(seq, offset, totalLen, Deleted: false);
            _tokenToId[tokenHex] = id;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buf.AsSpan(0, totalLen));
            ArrayPool<byte>.Shared.Return(buf);
        }

        await PersistIndexAsync(ct).ConfigureAwait(false);
    }

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
            return DecryptRecord(seg, expectedId: id);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    public async Task DeleteAsync(string id, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(id)) return;

        byte[] keyBytes = Encoding.UTF8.GetBytes(id);
        long seq = Interlocked.Increment(ref _nextSeq);
        byte[] token = MemoryBlockHelper.RandomBytes(TokenLen);

        (byte[] buf, int totalLen) = BuildRecord(1, seq, keyBytes, ReadOnlySpan<byte>.Empty, token);
        try
        {
            long offset = await _store.GetLengthAsync(ct).ConfigureAwait(false);
            await _store.AppendAsync(buf.AsMemory(0, totalLen), ct).ConfigureAwait(false);
            await _store.FlushAsync(true, ct).ConfigureAwait(false);
            _index[id] = new IndexEntry(seq, offset, totalLen, Deleted: true);
            _tokenToId[Convert.ToHexString(token)] = id; // needed so the tombstone token appears in the persisted index
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }

        await PersistIndexAsync(ct).ConfigureAwait(false);
    }

    public IReadOnlyCollection<string> ListIds() =>
        [.. _index.Where(kv => !kv.Value.Deleted).Select(kv => kv.Key)];

    public async Task CompactAsync(CancellationToken ct = default)
    {
        var liveIds = _index.Where(kv => !kv.Value.Deleted).Select(kv => kv.Key).ToArray();
        var newTokenMap = new Dictionary<string, string>(StringComparer.Ordinal);

        await _replacer.ReplaceWithAsync(async stream =>
        {
            await CopyHeaderBlobAsync(_store, stream, _sessionSaltLen, ct).ConfigureAwait(false);

            long newSeq = 0;
            foreach (string id in liveIds)
            {
                byte[]? pt = await GetAsync(id, ct).ConfigureAwait(false);
                if (pt is null) continue;

                byte[] keyBytes = Encoding.UTF8.GetBytes(id);
                long seq = Interlocked.Increment(ref newSeq);
                byte[] token = MemoryBlockHelper.RandomBytes(TokenLen);

                (byte[] rec, int len) = BuildRecord(0, seq, keyBytes, pt, token);
                try
                {
                    await stream.WriteAsync(rec.AsMemory(0, len), ct).ConfigureAwait(false);
                    newTokenMap[Convert.ToHexString(token)] = id;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(pt);
                    CryptographicOperations.ZeroMemory(rec.AsSpan(0, len));
                    ArrayPool<byte>.Shared.Return(rec);
                }
            }

            // Write the encrypted index record for the new token map into the new file.
            // Must happen inside ReplaceWithAsync so the index is part of the atomic rewrite.
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(newTokenMap);
            byte[] idxKey = "\x00IDX"u8.ToArray();
            byte[] idxToken = _indexToken.ToManagedCopy();
            long idxSeq = Interlocked.Increment(ref newSeq);

            (byte[] idxRec, int idxLen) = BuildRecord(0, idxSeq, idxKey, json, idxToken);
            try
            {
                await stream.WriteAsync(idxRec.AsMemory(0, idxLen), ct).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(idxRec.AsSpan(0, idxLen));
                ArrayPool<byte>.Shared.Return(idxRec);
                CryptographicOperations.ZeroMemory(idxToken);
                CryptographicOperations.ZeroMemory(json);
            }

            await stream.FlushAsync(ct).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);

        _tokenToId.Clear();
        foreach (var kv in newTokenMap)
            _tokenToId[kv.Key] = kv.Value;

        _index.Clear();
        _nextSeq = await RebuildIndexAsync(_store, ct).ConfigureAwait(false);
    }

    public async Task<VerifyResult> VerifyAsync(CancellationToken ct = default)
    {
        long pos = HeaderEndOffset(_sessionSaltLen);
        long fileLen = await _store.GetLengthAsync(ct).ConfigureAwait(false);

        int total = 0, valid = 0, corrupted = 0, truncated = 0;
        var corruptedKeys = new List<string>();
        var truncatedOffsets = new List<long>();

        while (pos < fileLen)
        {
            ct.ThrowIfCancellationRequested();

            int hdrLen = EncPrefixTotalLen + TokenLen;
            byte[] hdr = new byte[hdrLen];
            int got = await _store.ReadAtAsync(pos, hdr, ct).ConfigureAwait(false);

            if (got == 0) break;
            if (got != hdrLen)
            {
                truncated++;
                truncatedOffsets.Add(pos);
                break;
            }

            byte[] encPrefix = hdr[..EncPrefixTotalLen];
            byte[] token = hdr[EncPrefixTotalLen..];
            byte[] prefixPt = new byte[PrefixPlainLen];

            if (!TryDecryptPrefix(encPrefix, token, prefixPt))
            {
                corrupted++;
                corruptedKeys.Add($"<unknown@0x{pos:x}>");
                break;
            }

            int paddedCtLen = BinaryPrimitives.ReadInt32LittleEndian(prefixPt.AsSpan(21, 4));
            byte op = prefixPt[4];
            long seq = BinaryPrimitives.ReadInt64LittleEndian(prefixPt.AsSpan(5, 8));
            CryptographicOperations.ZeroMemory(prefixPt);

            int totalRecLen = EncPrefixTotalLen + TokenLen + paddedCtLen + GCMTagLen;

            byte[] fullRec = new byte[totalRecLen];
            hdr.CopyTo(fullRec.AsSpan(0, hdrLen));
            got = await _store.ReadAtAsync(pos + hdrLen, fullRec.AsMemory(hdrLen), ct)
                              .ConfigureAwait(false);

            if (got != totalRecLen - hdrLen)
            {
                truncated++;
                truncatedOffsets.Add(pos);
                break;
            }

            // Skip index records during verify — they are internal
            string tokenHex = Convert.ToHexString(token);
            bool isIndex = tokenHex == Convert.ToHexString(_indexToken.AsSpan());

            if (!isIndex)
            {
                total++;
                var seg = new ArraySegment<byte>(fullRec, 0, totalRecLen);
                byte[]? pt = DecryptRecord(seg, expectedId: null);

                if (pt is not null)
                {
                    CryptographicOperations.ZeroMemory(pt);
                    valid++;
                }
                else
                {
                    corrupted++;
                    string label = _tokenToId.TryGetValue(tokenHex, out var knownId)
                        ? knownId : $"<unknown@0x{pos:x}>";
                    corruptedKeys.Add(label);
                    _logger?.LogWarning(
                        "Record '{Key}' (seq={Seq}, offset=0x{Offset:x}) failed verification.",
                        label, seq, pos);
                }
            }

            pos += totalRecLen;
        }

        return new VerifyResult(total, valid, corrupted, truncated,
                                corruptedKeys.AsReadOnly(),
                                truncatedOffsets.AsReadOnly());
    }

    public async Task RotateDekAsync(
        byte[] currentPasswordUtf8,
        byte[]? newPasswordUtf8 = null,
        int? newSessionIters = null,
        int? newSessionSaltLen = null,
        IArgon2idParamsProvider? newDekArgonParams = null,
        CancellationToken ct = default)
    {
        if (currentPasswordUtf8 is null || currentPasswordUtf8.Length == 0)
            throw new ArgumentException("Current password is required.", nameof(currentPasswordUtf8));

        (byte[] candidateDek, _, _) = await ReadHeaderAsync(
            _store, _aead, currentPasswordUtf8,
            _sessionSaltLen, _sessionIters,
            new ArgonKeyProvider(), ct).ConfigureAwait(false);

        bool ok = CryptographicOperations.FixedTimeEquals(candidateDek.AsSpan(), _dek.AsSpan());
        CryptographicOperations.ZeroMemory(candidateDek);
        if (!ok)
            throw new CryptographicException("Current password is incorrect. Key rotation aborted.");

        byte[] targetPassword = newPasswordUtf8 ?? currentPasswordUtf8;
        int targetSaltLen = newSessionSaltLen ?? _sessionSaltLen;
        int targetSessionIters = newSessionIters ?? _sessionIters;

        byte[] newDek = MemoryBlockHelper.RandomBytes(DekLen);
        byte[] newNoncePrefix = MemoryBlockHelper.RandomBytes(NoncePrefixLen);
        byte[] newIndexToken = DeriveIndexToken(newDek);

        await RewriteWithNewKeyAsync(
            newDek, newNoncePrefix, newIndexToken,
            targetPassword, targetSessionIters, targetSaltLen,
            newDekArgonParams, ct).ConfigureAwait(false);

        SensitiveBytes oldDek = _dek;
        SensitiveBytes oldPrefix = _noncePrefix;
        SensitiveBytes oldToken = _indexToken;

        var freshDek = new SensitiveBytes(DekLen);
        var freshPrefix = new SensitiveBytes(NoncePrefixLen);
        var freshToken = new SensitiveBytes(TokenLen);

        newDek.AsSpan().CopyTo(freshDek.AsSpan());
        newNoncePrefix.AsSpan().CopyTo(freshPrefix.AsSpan());
        newIndexToken.AsSpan().CopyTo(freshToken.AsSpan());

        _dek = freshDek;
        _noncePrefix = freshPrefix;
        _indexToken = freshToken;

        // Update session parameters — may have changed if newSessionIters/newSessionSaltLen were passed
        _sessionIters = targetSessionIters;
        _sessionSaltLen = targetSaltLen;

        oldDek.Dispose();
        oldPrefix.Dispose();
        oldToken.Dispose();

        CryptographicOperations.ZeroMemory(newDek);
        CryptographicOperations.ZeroMemory(newNoncePrefix);
        CryptographicOperations.ZeroMemory(newIndexToken);

        _index.Clear();
        _nextSeq = await RebuildIndexAsync(_store, ct).ConfigureAwait(false);
        _logger?.LogDebug("DEK rotation completed.");
    }

    public async ValueTask DisposeAsync()
    {
        _dek.Dispose();
        _noncePrefix.Dispose();
        _indexToken.Dispose();
        await _store.FlushAsync(true).ConfigureAwait(false);
    }

    #endregion

    #region Record build / decrypt

    /// <summary>
    /// Builds a fully encrypted record.
    /// Payload plaintext = keyBytes || value || random_padding.
    /// Returns a rented ArrayPool buffer and its used length — caller must zero and return.
    /// </summary>
    private (byte[] Buffer, int Length) BuildRecord(
        byte op,
        long seq,
        byte[] keyBytes,
        ReadOnlySpan<byte> value,
        byte[] token)
    {
        // Payload = keyBytes || value, padded to paddedCtLen
        int ctLen = keyBytes.Length + value.Length;
        int padding = RandomNumberGenerator.GetInt32(0, MaxCtPadding + 1);
        int paddedCtLen = ctLen + padding;

        byte[] paddedPt = new byte[paddedCtLen];
        keyBytes.CopyTo(paddedPt.AsSpan(0, keyBytes.Length));
        value.CopyTo(paddedPt.AsSpan(keyBytes.Length, value.Length));
        if (padding > 0)
            RandomNumberGenerator.Fill(paddedPt.AsSpan(ctLen, padding));

        // Build and encrypt the 29-byte prefix
        byte[] prefixPt = new byte[PrefixPlainLen];
        RandomNumberGenerator.Fill(prefixPt.AsSpan(0, 4));                          // PreNoise
        prefixPt[4] = op;
        BinaryPrimitives.WriteInt64LittleEndian(prefixPt.AsSpan(5, 8), seq);
        BinaryPrimitives.WriteInt32LittleEndian(prefixPt.AsSpan(13, 4), keyBytes.Length);
        BinaryPrimitives.WriteInt32LittleEndian(prefixPt.AsSpan(17, 4), ctLen);
        BinaryPrimitives.WriteInt32LittleEndian(prefixPt.AsSpan(21, 4), paddedCtLen);
        RandomNumberGenerator.Fill(prefixPt.AsSpan(25, 4));                         // PostNoise

        byte[] prefixNonce = BuildPrefixNonce(token);
        byte[] encPrefixBuf = new byte[PrefixPlainLen];
        byte[] prefixTag = new byte[GCMTagLen];
        _aead.Encrypt(_dek.AsSpan(), prefixNonce, ReadOnlySpan<byte>.Empty,
                      prefixPt, encPrefixBuf, prefixTag);
        CryptographicOperations.ZeroMemory(prefixPt);

        // AAD for payload = EncPrefix (cipher + tag), 45 bytes
        byte[] aad = new byte[EncPrefixTotalLen];
        encPrefixBuf.CopyTo(aad.AsSpan(0, PrefixPlainLen));
        prefixTag.CopyTo(aad.AsSpan(PrefixPlainLen, GCMTagLen));

        // Encrypt payload
        byte[] payloadNonce = BuildPayloadNonce(seq);
        byte[] paddedCt = new byte[paddedCtLen];
        byte[] payloadTag = new byte[GCMTagLen];
        _aead.Encrypt(_dek.AsSpan(), payloadNonce, aad, paddedPt, paddedCt, payloadTag);
        CryptographicOperations.ZeroMemory(paddedPt);
        CryptographicOperations.ZeroMemory(aad);

        // Serialize: EncPrefix(45) | Token(16) | PaddedCt(paddedCtLen) | PayloadTag(16)
        int totalLen = EncPrefixTotalLen + TokenLen + paddedCtLen + GCMTagLen;
        byte[] buf = ArrayPool<byte>.Shared.Rent(totalLen);
        int off = 0;

        encPrefixBuf.CopyTo(buf.AsSpan(off, PrefixPlainLen)); off += PrefixPlainLen;
        prefixTag.CopyTo(buf.AsSpan(off, GCMTagLen)); off += GCMTagLen;
        token.CopyTo(buf.AsSpan(off, TokenLen)); off += TokenLen;
        paddedCt.CopyTo(buf.AsSpan(off, paddedCtLen)); off += paddedCtLen;
        payloadTag.CopyTo(buf.AsSpan(off, GCMTagLen));

        return (buf, totalLen);
    }

    /// <summary>
    /// Decrypts a record segment.
    /// If <paramref name="expectedId"/> is non-null, verifies the stored key matches.
    /// Returns the value bytes (key stripped), or null on any failure.
    /// </summary>
    private byte[]? DecryptRecord(ArraySegment<byte> seg, string? expectedId)
    {
        if (seg.Count < EncPrefixTotalLen + TokenLen + GCMTagLen) return null;

        int off = seg.Offset;

        byte[] encPrefix = seg.Array!.AsSpan(off, EncPrefixTotalLen).ToArray(); off += EncPrefixTotalLen;
        byte[] token = seg.Array.AsSpan(off, TokenLen).ToArray(); off += TokenLen;

        byte[] prefixPt = new byte[PrefixPlainLen];
        if (!TryDecryptPrefix(encPrefix, token, prefixPt)) return null;

        byte op = prefixPt[4];
        long seq = BinaryPrimitives.ReadInt64LittleEndian(prefixPt.AsSpan(5, 8));
        int keyLen = BinaryPrimitives.ReadInt32LittleEndian(prefixPt.AsSpan(13, 4));
        int ctLen = BinaryPrimitives.ReadInt32LittleEndian(prefixPt.AsSpan(17, 4));
        int paddedCtLen = BinaryPrimitives.ReadInt32LittleEndian(prefixPt.AsSpan(21, 4));
        CryptographicOperations.ZeroMemory(prefixPt);

        if (op > 1 || keyLen < 0 || ctLen < keyLen || paddedCtLen < ctLen) return null;
        if (seg.Count < EncPrefixTotalLen + TokenLen + paddedCtLen + GCMTagLen) return null;

        byte[] paddedCt = seg.Array.AsSpan(off, paddedCtLen).ToArray(); off += paddedCtLen;
        byte[] payloadTag = seg.Array.AsSpan(off, GCMTagLen).ToArray();

        byte[] aad = new byte[EncPrefixTotalLen];
        encPrefix.CopyTo(aad, 0);

        byte[] paddedPt = new byte[paddedCtLen];
        byte[] payloadNonce = BuildPayloadNonce(seq);
        bool ok;

        try
        {
            ok = _aead.Decrypt(_dek.AsSpan(), payloadNonce, aad, paddedCt, payloadTag, paddedPt);
        }
        catch (CryptographicException) { ok = false; }
        finally { CryptographicOperations.ZeroMemory(aad); }

        if (!ok) { CryptographicOperations.ZeroMemory(paddedPt); return null; }

        // Verify key if requested
        if (expectedId is not null)
        {
            string storedKey = Encoding.UTF8.GetString(paddedPt, 0, keyLen);
            if (!string.Equals(storedKey, expectedId, StringComparison.Ordinal))
            {
                CryptographicOperations.ZeroMemory(paddedPt);
                return null;
            }
        }

        // Extract value (strip key and padding)
        int valueLen = ctLen - keyLen;
        byte[] value = paddedPt.AsSpan(keyLen, valueLen).ToArray();
        CryptographicOperations.ZeroMemory(paddedPt);
        return value;
    }

    private bool TryDecryptPrefix(byte[] encPrefix, byte[] token, byte[] prefixPt)
    {
        byte[] nonce = BuildPrefixNonce(token);
        byte[] encBuf = encPrefix.AsSpan(0, PrefixPlainLen).ToArray();
        byte[] tag = encPrefix.AsSpan(PrefixPlainLen, GCMTagLen).ToArray();
        try
        {
            return _aead.Decrypt(_dek.AsSpan(), nonce, ReadOnlySpan<byte>.Empty,
                                 encBuf, tag, prefixPt);
        }
        catch (CryptographicException) { return false; }
    }

    #endregion

    #region Nonce helpers

    // Prefix nonce: NoncePrefix(4) || Token[4..12]
    private byte[] BuildPrefixNonce(byte[] token)
    {
        byte[] n = new byte[GCMNonceLen];
        _noncePrefix.AsSpan().CopyTo(n.AsSpan(0, NoncePrefixLen));
        token.AsSpan(4, 8).CopyTo(n.AsSpan(NoncePrefixLen, 8));
        return n;
    }

    // Payload nonce: NoncePrefix(4) || Seq_BE(8)
    private byte[] BuildPayloadNonce(long seq)
    {
        byte[] n = new byte[GCMNonceLen];
        _noncePrefix.AsSpan().CopyTo(n.AsSpan(0, NoncePrefixLen));
        BinaryPrimitives.WriteUInt64BigEndian(n.AsSpan(NoncePrefixLen, 8), (ulong)seq);
        return n;
    }

    private static byte[] BuildPayloadNonce(byte[] noncePrefix, long seq)
    {
        byte[] n = new byte[GCMNonceLen];
        noncePrefix.AsSpan(0, NoncePrefixLen).CopyTo(n.AsSpan(0, NoncePrefixLen));
        BinaryPrimitives.WriteUInt64BigEndian(n.AsSpan(NoncePrefixLen, 8), (ulong)seq);
        return n;
    }

    // Static prefix nonce for use during rewrite before _noncePrefix is swapped
    private static byte[] BuildPrefixNonce(byte[] noncePrefix, byte[] token)
    {
        byte[] n = new byte[GCMNonceLen];
        noncePrefix.AsSpan(0, NoncePrefixLen).CopyTo(n.AsSpan(0, NoncePrefixLen));
        token.AsSpan(4, 8).CopyTo(n.AsSpan(NoncePrefixLen, 8));
        return n;
    }

    #endregion

    #region Encrypted index

    // IndexToken = HMAC-SHA256(dek, "EES1_INDEX")[0..16]
    private static byte[] DeriveIndexToken(byte[] dek) =>
        HMACSHA256.HashData(dek, "EES1_INDEX"u8.ToArray())[..TokenLen];

    private async Task PersistIndexAsync(CancellationToken ct)
    {
        // Serialize the full token→id map including deleted entries.
        // Deleted state is tracked by Op in each record on disk — RebuildIndexAsync
        // reads Op and sets Deleted accordingly. Including all tokens ensures that
        // tombstone records are recognised at reopen; omitting deleted tokens would
        // cause a Delete+reopen to resurrect the entry.
        var map = _tokenToId.ToDictionary(kv => kv.Key, kv => kv.Value);

        byte[] json = JsonSerializer.SerializeToUtf8Bytes(map);
        byte[] idxKey = "\x00IDX"u8.ToArray(); // reserved key bytes, never a valid UTF-8 user id
        byte[] idxToken = _indexToken.ToManagedCopy();
        long seq = Interlocked.Increment(ref _nextSeq);

        (byte[] buf, int totalLen) = BuildRecord(0, seq, idxKey, json, idxToken);
        try
        {
            await _store.AppendAsync(buf.AsMemory(0, totalLen), ct).ConfigureAwait(false);
            await _store.FlushAsync(true, ct).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buf.AsSpan(0, totalLen));
            ArrayPool<byte>.Shared.Return(buf);
            CryptographicOperations.ZeroMemory(idxToken);
            CryptographicOperations.ZeroMemory(json);
        }
    }

    #endregion

    #region Index rebuild

    private async Task<long> RebuildIndexAsync(IAppendOnlyStoreProvider store, CancellationToken ct)
    {
        long startPos = HeaderEndOffset(_sessionSaltLen);
        long fileLen = await store.GetLengthAsync(ct).ConfigureAwait(false);
        string idxHex = Convert.ToHexString(_indexToken.AsSpan());

        // ── Pass 1: collect all record positions+sizes and load the token map ──
        // The index record is written AFTER the data records, so we must scan
        // the entire file before we can resolve token → id mappings.

        var rawRecords = new List<(long Pos, int TotalLen, string TokenHex, byte Op, long Seq, int KeyLen)>();
        var newTokenMap = new Dictionary<string, string>(StringComparer.Ordinal);

        long pos = startPos;
        while (pos < fileLen)
        {
            int hdrLen = EncPrefixTotalLen + TokenLen;
            byte[] hdr = new byte[hdrLen];
            int got = await store.ReadAtAsync(pos, hdr, ct).ConfigureAwait(false);
            if (got == 0) break;
            if (got != hdrLen) throw new InvalidDataException("Truncated record header.");

            byte[] encPrefix = hdr[..EncPrefixTotalLen];
            byte[] token = hdr[EncPrefixTotalLen..];
            byte[] prefixPt = new byte[PrefixPlainLen];

            if (!TryDecryptPrefix(encPrefix, token, prefixPt))
                throw new InvalidDataException("Record prefix decryption failed during index rebuild.");

            int paddedCtLen = BinaryPrimitives.ReadInt32LittleEndian(prefixPt.AsSpan(21, 4));
            int ctLen = BinaryPrimitives.ReadInt32LittleEndian(prefixPt.AsSpan(17, 4));
            int keyLen = BinaryPrimitives.ReadInt32LittleEndian(prefixPt.AsSpan(13, 4));
            byte op = prefixPt[4];
            long seq = BinaryPrimitives.ReadInt64LittleEndian(prefixPt.AsSpan(5, 8));
            CryptographicOperations.ZeroMemory(prefixPt);

            int totalRecLen = EncPrefixTotalLen + TokenLen + paddedCtLen + GCMTagLen;
            string tokenHex = Convert.ToHexString(token);

            if (tokenHex == idxHex)
            {
                // This is the encrypted index record — decrypt and load the token map
                byte[] recBuf = new byte[totalRecLen];
                hdr.CopyTo(recBuf.AsSpan(0, hdrLen));
                got = await store.ReadAtAsync(pos + hdrLen, recBuf.AsMemory(hdrLen), ct)
                                 .ConfigureAwait(false);
                if (got == totalRecLen - hdrLen)
                {
                    var seg = new ArraySegment<byte>(recBuf, 0, totalRecLen);
                    byte[]? idxPt = DecryptRecord(seg, expectedId: null);
                    if (idxPt is not null)
                    {
                        try
                        {
                            // DecryptRecord already strips keyBytes and returns value only.
                            // idxPt = json bytes directly — no offset needed.
                            var map = JsonSerializer.Deserialize<Dictionary<string, string>>(
                                idxPt.AsSpan(0, idxPt.Length));
                            if (map is not null)
                                foreach (var kv in map)
                                    newTokenMap[kv.Key] = kv.Value;
                        }
                        catch { /* corrupt index — will be rebuilt on next write */ }
                        finally { CryptographicOperations.ZeroMemory(idxPt); }
                    }
                }
            }
            else
            {
                // Data record — store position info for pass 2
                rawRecords.Add((pos, totalRecLen, tokenHex, op, seq, keyLen));
            }

            pos += totalRecLen;
        }

        // ── Pass 2: resolve token → id and build _index ──────────────────────

        var newIndex = new Dictionary<string, IndexEntry>(StringComparer.Ordinal);
        long maxSeq = 0;

        foreach (var (recPos, totalLen, tokenHex, op, seq, _) in rawRecords)
        {
            if (!newTokenMap.TryGetValue(tokenHex, out string? id))
                continue; // token not in index — orphaned record, skip

            // Keep only the latest record for each id (highest Seq wins)
            if (!newIndex.TryGetValue(id, out var existing) || seq > existing.Seq)
                newIndex[id] = new IndexEntry(seq, recPos, totalLen, Deleted: op == 1);

            if (seq > maxSeq) maxSeq = seq;
        }

        _index.Clear();
        foreach (var kv in newIndex) _index[kv.Key] = kv.Value;

        _tokenToId.Clear();
        foreach (var kv in newTokenMap) _tokenToId[kv.Key] = kv.Value;

        return maxSeq;
    }

    #endregion

    #region Header helpers

    private static long HeaderEndOffset(int sessionSaltLen) =>
        sessionSaltLen + EncryptedHeaderSize;

    private static async Task CopyHeaderBlobAsync(
        IAppendOnlyStoreProvider store, Stream dest, int sessionSaltLen, CancellationToken ct)
    {
        int total = sessionSaltLen + EncryptedHeaderSize;
        byte[] buf = new byte[total];
        int got = await store.ReadAtAsync(0, buf, ct).ConfigureAwait(false);
        if (got != total) throw new InvalidDataException("Incomplete header blob.");
        await dest.WriteAsync(buf, ct).ConfigureAwait(false);
    }

    private static void WriteHeader(
        Stream dest,
        byte[] dek,
        byte[] noncePrefix,
        byte[] indexToken,
        IAEADProvider aead,
        byte[] passwordUtf8,
        int sessionIters,
        int sessionSaltLen,
        IArgon2idParamsProvider? dekArgonParamsProvider,
        IArgonKeyProvider argonKeyProvider)
    {
        // 1. Random salt
        byte[] salt = MemoryBlockHelper.RandomBytes(sessionSaltLen);

        // 2. DEK Argon2id params
        var dekArgonProvider = dekArgonParamsProvider ?? new FixedArgon2idParamsProvider(
            new Argon2idParams(DefaultDekMemKiB, DefaultDekIters, DefaultDekPar));
        Argon2idParams dekParams = dekArgonProvider.GetParameters();
        byte[] dekArgonSalt = MemoryBlockHelper.RandomBytes(DekArgonSaltLen);

        // 3. Encrypt DEK with its own KEK derived from DEK Argon2id params
        var sessionParams = new Argon2idParams(SessionMemKiB, sessionIters, SessionParallelism);
        byte[] dekKek = argonKeyProvider.DeriveKey(passwordUtf8, dekArgonSalt, dekParams);
        byte[] dekNonce = MemoryBlockHelper.RandomBytes(GCMNonceLen);
        byte[] encDek = new byte[DekLen];
        byte[] dekTag = new byte[GCMTagLen];
        aead.Encrypt(dekKek, dekNonce, ReadOnlySpan<byte>.Empty, dek, encDek, dekTag);
        CryptographicOperations.ZeroMemory(dekKek);

        // 4. Build header plaintext (114 bytes)
        byte[] hdrPt = new byte[HeaderPlainMinLen];
        var s = hdrPt.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(s, InternalMagic); s = s[4..];
        s[0] = Version; s = s[1..];
        s[0] = GetAeadId(aead); s = s[1..];
        noncePrefix.CopyTo(s[..NoncePrefixLen]); s = s[NoncePrefixLen..];
        indexToken.CopyTo(s[..TokenLen]); s = s[TokenLen..];
        dekNonce.CopyTo(s[..GCMNonceLen]); s = s[GCMNonceLen..];
        encDek.CopyTo(s[..DekLen]); s = s[DekLen..];
        dekTag.CopyTo(s[..GCMTagLen]); s = s[GCMTagLen..];
        dekArgonSalt.CopyTo(s[..DekArgonSaltLen]); s = s[DekArgonSaltLen..];
        BinaryPrimitives.WriteInt32LittleEndian(s, dekParams.MemoryKiB); s = s[4..];
        BinaryPrimitives.WriteInt32LittleEndian(s, dekParams.Iterations); s = s[4..];
        BinaryPrimitives.WriteInt32LittleEndian(s, dekParams.Parallelism);

        // 5. Pad to EncryptedHeaderSize - GCMTagLen, then encrypt with session KEK
        int ptLen = EncryptedHeaderSize - GCMTagLen;
        byte[] padded = new byte[ptLen];
        hdrPt.CopyTo(padded.AsSpan(0, HeaderPlainMinLen));
        RandomNumberGenerator.Fill(padded.AsSpan(HeaderPlainMinLen));
        CryptographicOperations.ZeroMemory(hdrPt);

        // hdrNonce = first 12 bytes of salt (salt is already random)
        byte[] hdrNonce = salt[..GCMNonceLen];
        byte[] kek = argonKeyProvider.DeriveKey(passwordUtf8, salt, sessionParams);
        byte[] ctBuf = new byte[ptLen];
        byte[] hdrTag = new byte[GCMTagLen];
        aead.Encrypt(kek, hdrNonce, ReadOnlySpan<byte>.Empty, padded, ctBuf, hdrTag);
        CryptographicOperations.ZeroMemory(kek);
        CryptographicOperations.ZeroMemory(padded);

        // 6. Write: salt(saltLen) | ctBuf(ptLen) | hdrTag(16)  = saltLen + 512 bytes total
        dest.Write(salt);
        dest.Write(ctBuf);
        dest.Write(hdrTag);
    }

    private static async Task<(byte[] Dek, byte[] NoncePrefix, byte[] IndexToken)> ReadHeaderAsync(
        IAppendOnlyStoreProvider store,
        IAEADProvider aead,
        byte[] passwordUtf8,
        int sessionSaltLen,
        int sessionIters,
        IArgonKeyProvider argonKeyProvider,
        CancellationToken ct)
    {
        int total = sessionSaltLen + EncryptedHeaderSize;
        byte[] buf = new byte[total];
        int got = await store.ReadAtAsync(0, buf, ct).ConfigureAwait(false);
        if (got != total) throw new InvalidDataException("Incomplete header blob.");

        byte[] salt = buf[..sessionSaltLen];
        int ptLen = EncryptedHeaderSize - GCMTagLen;
        byte[] ctBuf = buf[sessionSaltLen..^GCMTagLen];
        byte[] hdrTag = buf[^GCMTagLen..];

        var sessionParams = new Argon2idParams(SessionMemKiB, sessionIters, SessionParallelism);
        byte[] hdrNonce = salt[..GCMNonceLen];
        byte[] kek = argonKeyProvider.DeriveKey(passwordUtf8, salt, sessionParams);
        byte[] ptBuf = new byte[ptLen];

        bool ok;
        try { ok = aead.Decrypt(kek, hdrNonce, ReadOnlySpan<byte>.Empty, ctBuf, hdrTag, ptBuf); }
        catch (CryptographicException) { ok = false; }
        finally { CryptographicOperations.ZeroMemory(kek); }

        if (!ok)
        {
            CryptographicOperations.ZeroMemory(ptBuf);
            throw new CryptographicException(
                "Failed to decrypt store header. Password, session iterations, or salt length is incorrect.");
        }

        var sp = ptBuf.AsSpan();
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(sp); sp = sp[4..];
        if (magic != InternalMagic)
        {
            CryptographicOperations.ZeroMemory(ptBuf);
            throw new InvalidDataException("Wrong internal magic. Not an EES store or data corrupted.");
        }

        byte ver = sp[0]; sp = sp[1..];
        if (ver != Version)
        {
            CryptographicOperations.ZeroMemory(ptBuf);
            throw new NotSupportedException($"Store version 0x{ver:x2} not supported (expected 0x{Version:x2}).");
        }

        byte aeadId = sp[0]; sp = sp[1..];
        if (aeadId != GetAeadId(aead))
        {
            CryptographicOperations.ZeroMemory(ptBuf);
            throw new InvalidOperationException(
                $"Store AEAD 0x{aeadId:x2} does not match provider '{aead.Name}'.");
        }

        byte[] noncePrefix = sp[..NoncePrefixLen].ToArray(); sp = sp[NoncePrefixLen..];
        byte[] indexToken = sp[..TokenLen].ToArray(); sp = sp[TokenLen..];
        byte[] dekNonce = sp[..GCMNonceLen].ToArray(); sp = sp[GCMNonceLen..];
        byte[] encDek = sp[..DekLen].ToArray(); sp = sp[DekLen..];
        byte[] dekTag = sp[..GCMTagLen].ToArray(); sp = sp[GCMTagLen..];
        byte[] dekArgonSalt = sp[..DekArgonSaltLen].ToArray(); sp = sp[DekArgonSaltLen..];
        int memKiB = BinaryPrimitives.ReadInt32LittleEndian(sp); sp = sp[4..];
        int iters = BinaryPrimitives.ReadInt32LittleEndian(sp); sp = sp[4..];
        int par = BinaryPrimitives.ReadInt32LittleEndian(sp);
        CryptographicOperations.ZeroMemory(ptBuf);

        var dekParams = new Argon2idParams(memKiB, iters, par);
        byte[] dekKek = argonKeyProvider.DeriveKey(passwordUtf8, dekArgonSalt, dekParams);
        byte[] dek = new byte[DekLen];
        bool dekOk;
        try { dekOk = aead.Decrypt(dekKek, dekNonce, ReadOnlySpan<byte>.Empty, encDek, dekTag, dek); }
        catch (CryptographicException) { dekOk = false; }
        finally { CryptographicOperations.ZeroMemory(dekKek); }

        if (!dekOk)
        {
            CryptographicOperations.ZeroMemory(dek);
            throw new CryptographicException("Failed to decrypt the store DEK.");
        }

        return (dek, noncePrefix, indexToken);
    }

    private static byte GetAeadId(IAEADProvider aead) => aead switch
    {
        AesCtrHmacSha256Provider => (byte)AeadAlgorithmId.AesCtrHmacSha256,
        AesGcmProvider => (byte)AeadAlgorithmId.AesGcm,
        _ => aead.Name switch
        {
            "AES-GCM" => (byte)AeadAlgorithmId.AesGcm,
            "ChaCha20-Poly1305" => (byte)AeadAlgorithmId.ChaCha20Poly1305,
            "AES-CTR+HMAC-SHA256 (EtM)" => (byte)AeadAlgorithmId.AesCtrHmacSha256,
            _ => throw new NotSupportedException($"Cannot determine AeadAlgorithmId for '{aead.Name}'.")
        }
    };

    #endregion

    #region RewriteWithNewKey

    private async Task RewriteWithNewKeyAsync(
        byte[] newDek,
        byte[] newNoncePrefix,
        byte[] newIndexToken,
        byte[] passwordUtf8,
        int sessionIters,
        int sessionSaltLen,
        IArgon2idParamsProvider? dekArgonParams,
        CancellationToken ct)
    {
        var liveIds = _index.Where(kv => !kv.Value.Deleted).Select(kv => kv.Key).ToArray();
        var snapshots = new List<(string Id, byte[] Pt)>(liveIds.Length);
        foreach (string id in liveIds)
        {
            byte[]? pt = await GetAsync(id, ct).ConfigureAwait(false);
            if (pt is not null) snapshots.Add((id, pt));
        }

        var newTokenMap = new Dictionary<string, string>(StringComparer.Ordinal);

        await _replacer.ReplaceWithAsync(async stream =>
        {
            using var ms = new MemoryStream(DefaultMemBufDim);
            WriteHeader(ms, newDek, newNoncePrefix, newIndexToken, _aead,
                        passwordUtf8, sessionIters, sessionSaltLen,
                        dekArgonParams, new ArgonKeyProvider());
            await stream.WriteAsync(ms.ToArray(), ct).ConfigureAwait(false);

            long newSeq = 0;
            foreach (var (id, pt) in snapshots)
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(id);
                long seq = Interlocked.Increment(ref newSeq);
                byte[] token = MemoryBlockHelper.RandomBytes(TokenLen);

                int ctLen = keyBytes.Length + pt.Length;
                int padding = RandomNumberGenerator.GetInt32(0, MaxCtPadding + 1);
                int paddedCtLen = ctLen + padding;

                byte[] combinedPt = new byte[paddedCtLen];
                keyBytes.CopyTo(combinedPt.AsSpan(0, keyBytes.Length));
                pt.CopyTo(combinedPt.AsSpan(keyBytes.Length, pt.Length));
                if (padding > 0)
                    RandomNumberGenerator.Fill(combinedPt.AsSpan(ctLen, padding));

                byte[] prefixPt = new byte[PrefixPlainLen];
                RandomNumberGenerator.Fill(prefixPt.AsSpan(0, 4));
                prefixPt[4] = 0;
                BinaryPrimitives.WriteInt64LittleEndian(prefixPt.AsSpan(5, 8), seq);
                BinaryPrimitives.WriteInt32LittleEndian(prefixPt.AsSpan(13, 4), keyBytes.Length);
                BinaryPrimitives.WriteInt32LittleEndian(prefixPt.AsSpan(17, 4), ctLen);
                BinaryPrimitives.WriteInt32LittleEndian(prefixPt.AsSpan(21, 4), paddedCtLen);
                RandomNumberGenerator.Fill(prefixPt.AsSpan(25, 4));

                byte[] prefixNonce = BuildPrefixNonce(newNoncePrefix, token);
                byte[] encPrefixBuf = new byte[PrefixPlainLen];
                byte[] prefixTag = new byte[GCMTagLen];
                _aead.Encrypt(newDek, prefixNonce, ReadOnlySpan<byte>.Empty,
                              prefixPt, encPrefixBuf, prefixTag);
                CryptographicOperations.ZeroMemory(prefixPt);

                byte[] aad = new byte[EncPrefixTotalLen];
                encPrefixBuf.CopyTo(aad.AsSpan(0, PrefixPlainLen));
                prefixTag.CopyTo(aad.AsSpan(PrefixPlainLen, GCMTagLen));

                byte[] payloadNonce = BuildPayloadNonce(newNoncePrefix, seq);
                byte[] paddedCt = new byte[paddedCtLen];
                byte[] payloadTag = new byte[GCMTagLen];
                _aead.Encrypt(newDek, payloadNonce, aad, combinedPt, paddedCt, payloadTag);
                CryptographicOperations.ZeroMemory(combinedPt);
                CryptographicOperations.ZeroMemory(aad);

                int totalLen = EncPrefixTotalLen + TokenLen + paddedCtLen + GCMTagLen;
                byte[] recBuf = new byte[totalLen];
                int off = 0;
                encPrefixBuf.CopyTo(recBuf.AsSpan(off, PrefixPlainLen)); off += PrefixPlainLen;
                prefixTag.CopyTo(recBuf.AsSpan(off, GCMTagLen)); off += GCMTagLen;
                token.CopyTo(recBuf.AsSpan(off, TokenLen)); off += TokenLen;
                paddedCt.CopyTo(recBuf.AsSpan(off, paddedCtLen)); off += paddedCtLen;
                payloadTag.CopyTo(recBuf.AsSpan(off, GCMTagLen));

                await stream.WriteAsync(recBuf.AsMemory(0, totalLen), ct).ConfigureAwait(false);
                newTokenMap[Convert.ToHexString(token)] = id;
            }

            // Write the encrypted index record for the new token map.
            // Uses the new DEK and new IndexToken — built inline because _dek/_indexToken
            // still point to the old key material at this point in the rewrite.
            byte[] idxJson = JsonSerializer.SerializeToUtf8Bytes(newTokenMap);
            byte[] idxKeyB = "\x00IDX"u8.ToArray();
            long idxSeq = Interlocked.Increment(ref newSeq);

            // Build prefix plaintext manually with new key material
            int idxCtLen = idxKeyB.Length + idxJson.Length;
            int idxPadding = RandomNumberGenerator.GetInt32(0, MaxCtPadding + 1);
            int idxPaddedCtLen = idxCtLen + idxPadding;
            byte[] idxCombined = new byte[idxPaddedCtLen];
            idxKeyB.CopyTo(idxCombined.AsSpan(0, idxKeyB.Length));
            idxJson.CopyTo(idxCombined.AsSpan(idxKeyB.Length, idxJson.Length));
            if (idxPadding > 0)
                RandomNumberGenerator.Fill(idxCombined.AsSpan(idxCtLen, idxPadding));

            byte[] idxPrefixPt = new byte[PrefixPlainLen];
            RandomNumberGenerator.Fill(idxPrefixPt.AsSpan(0, 4));
            idxPrefixPt[4] = 0;
            BinaryPrimitives.WriteInt64LittleEndian(idxPrefixPt.AsSpan(5, 8), idxSeq);
            BinaryPrimitives.WriteInt32LittleEndian(idxPrefixPt.AsSpan(13, 4), idxKeyB.Length);
            BinaryPrimitives.WriteInt32LittleEndian(idxPrefixPt.AsSpan(17, 4), idxCtLen);
            BinaryPrimitives.WriteInt32LittleEndian(idxPrefixPt.AsSpan(21, 4), idxPaddedCtLen);
            RandomNumberGenerator.Fill(idxPrefixPt.AsSpan(25, 4));

            byte[] idxPrefixNonce = BuildPrefixNonce(newNoncePrefix, newIndexToken);
            byte[] idxEncPrefixBuf = new byte[PrefixPlainLen];
            byte[] idxPrefixTag = new byte[GCMTagLen];
            _aead.Encrypt(newDek, idxPrefixNonce, ReadOnlySpan<byte>.Empty,
                          idxPrefixPt, idxEncPrefixBuf, idxPrefixTag);
            CryptographicOperations.ZeroMemory(idxPrefixPt);

            byte[] idxAad = new byte[EncPrefixTotalLen];
            idxEncPrefixBuf.CopyTo(idxAad.AsSpan(0, PrefixPlainLen));
            idxPrefixTag.CopyTo(idxAad.AsSpan(PrefixPlainLen, GCMTagLen));

            byte[] idxPayloadNonce = BuildPayloadNonce(newNoncePrefix, idxSeq);
            byte[] idxPaddedCt = new byte[idxPaddedCtLen];
            byte[] idxPayloadTag = new byte[GCMTagLen];
            _aead.Encrypt(newDek, idxPayloadNonce, idxAad, idxCombined, idxPaddedCt, idxPayloadTag);
            CryptographicOperations.ZeroMemory(idxCombined);
            CryptographicOperations.ZeroMemory(idxAad);

            int idxTotalLen = EncPrefixTotalLen + TokenLen + idxPaddedCtLen + GCMTagLen;
            byte[] idxRecBuf = new byte[idxTotalLen];
            int idxOff = 0;
            idxEncPrefixBuf.CopyTo(idxRecBuf.AsSpan(idxOff, PrefixPlainLen)); idxOff += PrefixPlainLen;
            idxPrefixTag.CopyTo(idxRecBuf.AsSpan(idxOff, GCMTagLen)); idxOff += GCMTagLen;
            newIndexToken.CopyTo(idxRecBuf.AsSpan(idxOff, TokenLen)); idxOff += TokenLen;
            idxPaddedCt.CopyTo(idxRecBuf.AsSpan(idxOff, idxPaddedCtLen)); idxOff += idxPaddedCtLen;
            idxPayloadTag.CopyTo(idxRecBuf.AsSpan(idxOff, GCMTagLen));

            await stream.WriteAsync(idxRecBuf.AsMemory(0, idxTotalLen), ct).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(idxJson);

            await stream.FlushAsync(ct).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);

        foreach (var (_, pt) in snapshots)
            CryptographicOperations.ZeroMemory(pt);

        _tokenToId.Clear();
        foreach (var kv in newTokenMap)
            _tokenToId[kv.Key] = kv.Value;
    }

    #endregion

    #region OpenCoreAsync

    internal static async Task<EncryptedEntryStore> OpenCoreAsync(
        IAppendOnlyStoreProvider store,
        IAtomicReplace replacer,
        IAEADProvider aead,
        byte[] passwordUtf8,
        int sessionIters,
        int sessionSaltLen,
        IArgon2idParamsProvider? dekArgonParams,
        IArgonKeyProvider argonKeyProvider,
        ILogger? logger,
        CancellationToken ct)
    {
        long len = await store.GetLengthAsync(ct).ConfigureAwait(false);

        if (len == 0)
        {
            byte[] dek = MemoryBlockHelper.RandomBytes(DekLen);
            byte[] noncePrefix = MemoryBlockHelper.RandomBytes(NoncePrefixLen);
            byte[] indexToken = DeriveIndexToken(dek);

            using var ms = new MemoryStream(DefaultMemBufDim);
            WriteHeader(ms, dek, noncePrefix, indexToken, aead,
                        passwordUtf8, sessionIters, sessionSaltLen,
                        dekArgonParams, argonKeyProvider);

            await store.AppendAsync(ms.ToArray(), ct).ConfigureAwait(false);
            await store.FlushAsync(true, ct).ConfigureAwait(false);

            return new EncryptedEntryStore(store, replacer, aead,
                                           dek, noncePrefix, indexToken,
                                           sessionSaltLen, sessionIters,
                                           nextSeq: 0, logger);
        }
        else
        {
            (byte[] dek, byte[] noncePrefix, byte[] indexToken) =
                await ReadHeaderAsync(store, aead, passwordUtf8,
                                      sessionSaltLen, sessionIters,
                                      argonKeyProvider, ct).ConfigureAwait(false);

            var instance = new EncryptedEntryStore(store, replacer, aead,
                                                   dek, noncePrefix, indexToken,
                                                   sessionSaltLen, sessionIters,
                                                   nextSeq: 0, logger);

            long nextSeq = await instance.RebuildIndexAsync(store, ct).ConfigureAwait(false);
            instance._nextSeq = nextSeq;

            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(noncePrefix);
            CryptographicOperations.ZeroMemory(indexToken);

            return instance;
        }
    }

    #endregion
}