using Hoddmir.Core.Encryption;
using Hoddmir.Core.Keys;
using Hoddmir.Core.Keys.Calibration;
using Hoddmir.Core.Memory;
using Microsoft.Extensions.Logging;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Hoddmir.Storage
{
    public sealed class EncryptedEntryStore 
        : IAsyncDisposable
    {
        // File format (little endian)
        // [MAGIC(4)="EES1"][VER(1)=0x01][KeyMode(1)][HeaderLen(4)][HeaderPayload]
        // Record:
        //  byte  Op (0=Put, 1=Delete)
        //  long  Seq
        //  int   KeyLen
        //  int   CtLen
        //  12B   Nonce
        //  Key   (KeyLen UTF8)
        //  Ct    (CtLen)
        //  16B   Tag
        // AAD = Op||Seq||KeyLen||CtLen

        #region Consts

        private const int DefaultMemoryBufferDimension = 256;

        private const int DefaultIteractions = 600000;

        private const uint MagicNumber = 0x31455345; // "EES1"
        private const byte Version = 0x01;
        private const int GCMNonceLen = 12;
        private const int GCMTagLen = 16;

        #endregion

        #region Fields

        private readonly IAppendOnlyStoreProvider storeProvider;
        private readonly IAtomicReplace replacer;
        private readonly IAEADProvider aeadProvider;
        private readonly SensitiveBytes dek;

        private long nextSeq;
        private readonly ConcurrentDictionary<string, IndexEntry> index = new(StringComparer.Ordinal);

        private record struct IndexEntry(long Seq, long Offset, int TotalLen, bool Deleted);

        #endregion

        #region Properties

        private ILogger? Logger
        {
            get;
        }

        #endregion

        #region .ctor

        private EncryptedEntryStore(IAppendOnlyStoreProvider storeProvider, 
                                    IAtomicReplace replacer, 
                                    IAEADProvider aeadProvider,
                                    byte[] dek, 
                                    long nextSeq,
                                    ILogger? logger = null)
        {
            this.storeProvider = storeProvider;
            this.replacer = replacer;
            this.dek = new SensitiveBytes(32);
            this.aeadProvider = aeadProvider;

            dek.CopyTo(this.dek.AsSpan());

            CryptographicOperations.ZeroMemory(dek);

            this.nextSeq = nextSeq;
            this.Logger = logger;
        }

        #endregion

        // Open with password as UTF-8 bytes (no string)
        public static async Task<EncryptedEntryStore> OpenAsync(IAppendOnlyStoreProvider storeProvider,
                                                                IAtomicReplace replacer,
                                                                IAEADProvider aeadProvider,
                                                                KeyProtectionMode mode,
                                                                byte[] passwordUtf8,
                                                                IArgon2idParamsProvider? argonParamsProvider = null,
                                                                IArgonKeyProvider? argonKeyProvider = null,
                                                                CancellationToken cancellationToken = default)
        {
            EncryptedEntryStore encryptedEntryStore;

            // if length 0 -> create new, else open and rebuild

            long len = await storeProvider.GetLengthAsync(cancellationToken)
                                .ConfigureAwait(false);           

            if (len == 0)
            {
                byte[] dek = MemoryBlockHelper.RandomBytes(32);

                // Write headers

                using MemoryStream ms = new (DefaultMemoryBufferDimension);

                WriteHeader(ms, 
                            dek, 
                            mode, 
                            passwordUtf8, 
                            argonParamsProvider,
                            aeadProvider, 
                            argonKeyProvider);

                await storeProvider.AppendAsync(ms.ToArray(), cancellationToken)
                         .ConfigureAwait(false);
                await storeProvider.FlushAsync(true, cancellationToken)
                         .ConfigureAwait(false);
                encryptedEntryStore =  new (storeProvider, 
                                            replacer, 
                                            aeadProvider,
                                            dek, 
                                            nextSeq: 0);
            }
            else
            {               

                // Read headers

                (byte[] dek, KeyProtectionMode _) = await ReadHeaderAsync(storeProvider,
                                                                          aeadProvider,
                                                                          mode, 
                                                                          passwordUtf8,
                                                                          cancellationToken: cancellationToken)
                                                         .ConfigureAwait(false);
                long nextSeq = await RebuildIndexAsync(storeProvider, dek, cancellationToken).ConfigureAwait(false);
                encryptedEntryStore = new (storeProvider,
                                           replacer,
                                           aeadProvider,
                                           dek, 
                                           nextSeq);
            }

            return encryptedEntryStore;
        }

        // Back-compat: string (sconsigliato, ma utile)
        public static Task<EncryptedEntryStore> OpenAsync(IAppendOnlyStoreProvider dev,
                                                          IAtomicReplace replacer,
                                                          IAEADProvider aeadProvider,
                                                          KeyProtectionMode mode,
                                                          string? password,
                                                          IArgon2idParamsProvider? argonParams = null,
                                                          IArgonKeyProvider? argonKeyProvider = null,
                                                          CancellationToken cancellationToken = default)
        {
            byte[]? pw = password is null ? [] : Encoding.UTF8.GetBytes(password);
            return OpenAsync(dev, 
                             replacer, 
                             aeadProvider,
                             mode, 
                             pw, 
                             argonParams, 
                             argonKeyProvider, 
                             cancellationToken);
        }



        public async Task PutAsync(string id, 
                                   ReadOnlyMemory<byte> value, 
                                   CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(id)) 
                throw new ArgumentException("Empty ID");

            byte[] keyBytes = Encoding.UTF8.GetBytes(id);
            byte[] nonce = MemoryBlockHelper.RandomBytes(GCMNonceLen);
            long seq = Interlocked.Increment(ref nextSeq);
            byte op = 0;

            byte[] aad = new byte[17];
            aad[0] = op;
            
            BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan()[1..], seq);
            BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan()[9..], keyBytes.Length);
            BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan()[13..], value.Length);

            byte[] cipherTextBuffer = new byte[value.Length];
            byte[] tag = new byte[GCMTagLen];

            // byte[] tmpKey;

            this.aeadProvider.Encrypt(dek.AsSpan(),
                                      nonce.AsSpan(),
                                      aad.AsSpan(),
                                      value.Span,
                                      cipherTextBuffer.AsSpan(),
                                      tag.AsSpan());            

            // serialize record
            int total = 1 + 8 + 4 + 4 + GCMNonceLen + keyBytes.Length + cipherTextBuffer.Length + GCMTagLen;
            byte[] buf = ArrayPool<byte>.Shared.Rent(total);
            try
            {
                ArraySegment<byte> span = new (buf, 0, total);
                int off = 0;
                span[off++] = op;
                BinaryPrimitives.WriteInt64LittleEndian(span.Slice(off, 8), seq); off += 8;
                BinaryPrimitives.WriteInt32LittleEndian(span.Slice(off, 4), keyBytes.Length); off += 4;
                BinaryPrimitives.WriteInt32LittleEndian(span.Slice(off, 4), cipherTextBuffer.Length); off += 4;

                Buffer.BlockCopy(nonce, 0, span.Array!, span.Offset + off, GCMNonceLen);
                off += GCMNonceLen;

                Buffer.BlockCopy(keyBytes, 0, span.Array!, span.Offset + off, keyBytes.Length);
                off += keyBytes.Length;

                Buffer.BlockCopy(cipherTextBuffer, 0, span.Array!, span.Offset + off, cipherTextBuffer.Length);
                off += cipherTextBuffer.Length;

                Buffer.BlockCopy(tag, 0, span.Array!, span.Offset + off, GCMTagLen);
                off += GCMTagLen;

                long currentLen = await storeProvider.GetLengthAsync(cancellationToken).ConfigureAwait(false);
                await storeProvider.AppendAsync(span.Slice(0, total).ToArray(), cancellationToken).ConfigureAwait(false);
                await storeProvider.FlushAsync(true, cancellationToken).ConfigureAwait(false);

                index[id] = new IndexEntry(seq, currentLen, total, Deleted: false);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
                CryptographicOperations.ZeroMemory(cipherTextBuffer);
            }
        }

        public async Task<byte[]?> GetAsync(string id, 
                                            CancellationToken cancellationToken = default)
        {
            if (!index.TryGetValue(id, out var idx) || idx.Deleted) 
                return null;

            // Read raw record
            byte[] rented = ArrayPool<byte>.Shared.Rent(idx.TotalLen);

            try
            {
                ArraySegment<byte> span = new(rented, 0, idx.TotalLen);
                int read = await storeProvider.ReadAtAsync(idx.Offset, span, cancellationToken).ConfigureAwait(false);

                if (read != idx.TotalLen) 
                    return null;

                int off = 0;
                byte op = span[off++]; 

                if (op != 0) 
                    return null;

                long seq = BinaryPrimitives.ReadInt64LittleEndian(span.Slice(off, 8)); off += 8;
                int keyLen = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(off, 4)); off += 4;
                int ctLen = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(off, 4)); off += 4;

                var nonce = span.Slice(off, GCMNonceLen).ToArray(); 
                off += GCMNonceLen;

                var keyBytes = span.Slice(off, keyLen).ToArray(); 
                off += keyLen;

                var ctBuf = span.Slice(off, ctLen).ToArray(); 
                off += ctLen;

                var tag = span.Slice(off, GCMTagLen).ToArray();

                var keyStr = Encoding.UTF8.GetString(keyBytes);

                if (!string.Equals(keyStr, id, StringComparison.Ordinal)) 
                    return null;

                byte[] aad = new byte[17];
                aad[0] = op;
                BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan()[1..], seq);
                BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan()[9..], keyLen);
                BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan()[13..], ctLen);

                byte[] pt = new byte[ctLen];
                try
                {
                    // byte[] tmpKey;

                    aeadProvider.Decrypt(dek.AsSpan(), 
                                         nonce.AsSpan(), 
                                         aad.AsSpan(),
                                         ctBuf.AsSpan(), 
                                         tag.AsSpan(), 
                                         pt.AsSpan());

                    //using var gcm = CreateGcm(out tmpKey);
                    //gcm.Decrypt(nonce.AsSpan(), 
                    //            ctBuf.AsSpan(), 
                    //            tag.AsSpan(), 
                    //            pt.AsSpan(), 
                    //            aad.AsSpan());
                    // CryptographicOperations.ZeroMemory(tmpKey);
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

        public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(id)) 
                return;

            byte[] keyBytes = Encoding.UTF8.GetBytes(id);
            byte[] nonce = MemoryBlockHelper.RandomBytes(GCMNonceLen);
            long seq = Interlocked.Increment(ref nextSeq);
            byte op = 1;
            int keyLen = keyBytes.Length, ctLen = 0;

            byte[] aad = new byte [17];
            aad[0] = op;

            BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan()[1..], seq);
            BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan()[9..], keyLen);
            BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan()[13..], ctLen);

            byte[] tag = new byte[GCMTagLen];
            // byte[] tmpKey;

            // using (AesGcm gcm = CreateGcm(out tmpKey))
            // gcm.Encrypt(nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, aad);

            aeadProvider.Encrypt(dek.AsSpan(), 
                                 nonce.AsSpan(), 
                                 aad.AsSpan(),
                                 ReadOnlySpan<byte>.Empty, 
                                 Span<byte>.Empty, 
                                 tag.AsSpan());

            // CryptographicOperations.ZeroMemory(tmpKey);
            CryptographicOperations.ZeroMemory(aad);

            int total = 1 + 8 + 4 + 4 + GCMNonceLen + keyLen + 0 + GCMTagLen;
            byte[] buf = ArrayPool<byte>.Shared.Rent(total);
            try
            {
                ArraySegment<byte> span = new (buf, 0, total);
                int off = 0;
                span[off++] = op;

                BinaryPrimitives.WriteInt64LittleEndian(span.Slice(off, 8), seq); 
                off += 8;

                BinaryPrimitives.WriteInt32LittleEndian(span.Slice(off, 4), keyLen); 
                off += 4;

                BinaryPrimitives.WriteInt32LittleEndian(span.Slice(off, 4), 0); 
                off += 4;

                // nonce.CopyTo(span.Slice(off, GCM_NONCE_LEN)); off += GCM_NONCE_LEN;
                // keyBytes.CopyTo(span.Slice(off, keyLen)); off += keyLen;
                // tag.CopyTo(span.Slice(off, GCM_TAG_LEN));

                nonce = span.Slice(off, GCMNonceLen).ToArray();
                off += GCMNonceLen;

                keyBytes = span.Slice(off, keyLen).ToArray();
                off += keyLen;

                tag = span.Slice(off, GCMTagLen).ToArray();

                long currentLen = await storeProvider.GetLengthAsync(cancellationToken)
                                                     .ConfigureAwait(false);
                await storeProvider.AppendAsync(span.Slice(0, total).ToArray(), cancellationToken)
                                   .ConfigureAwait(false);
                await storeProvider.FlushAsync(true, cancellationToken)
                                   .ConfigureAwait(false);

                index[id] = new IndexEntry(seq, currentLen, total, Deleted: true);
            }
            finally 
            {
                ArrayPool<byte>.Shared.Return(buf); 
            }
        }

        public IReadOnlyCollection<string> ListIds()
        {
            string[] indexes = [.. this.index.Where(kv => !kv.Value.Deleted)
                                             .Select(kv => kv.Key)];
            return indexes;
        }

        public async Task CompactAsync(CancellationToken cancellationToken = default)
        {
            await this.replacer.ReplaceWithAsync(async stream =>
            {
                // 1) Header identico
                await CopyHeaderAsync(this.storeProvider, 
                                      stream, 
                                      cancellationToken)
                     .ConfigureAwait(false);

                // 2) Riscrivi solo i record vivi, con nuovi seq e nuovi nonce
                string[] liveIds = this.index.Where(kv => !kv.Value.Deleted)
                                             .Select(kv => kv.Key)
                                             .ToArray();
                long newSeq = 0;

                foreach (var id in liveIds)
                {
                    var plaintext = await GetAsync(id, cancellationToken).ConfigureAwait(false);
                    if (plaintext is null) continue; // se non decifrabile, salta

                    byte op = 0;
                    var keyBytes = Encoding.UTF8.GetBytes(id);
                    var nonce = MemoryBlockHelper.RandomBytes(this.aeadProvider.NonceSizeBytes);
                    var seq = Interlocked.Increment(ref newSeq);

                    // AAD = Op(1) | Seq(8) | KeyLen(4) | CtLen(4)
                    // Prima cifra per ottenere ctBuf/tag
                    var ctBuf = new byte[plaintext.Length];
                    var tag = new byte[this.aeadProvider.TagSizeBytes];

                    // compila AAD con ctLen **corretto**
                    byte[] aad = new byte[17];
                    aad[0] = op;
                    BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan(1, 8), seq);
                    BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(9, 4), keyBytes.Length);
                    BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(13, 4), ctBuf.Length);

                    var tmpKey = this.dek.ToManagedCopy();
                    try
                    {
                        this.aeadProvider.Encrypt(tmpKey.AsSpan(),
                                                  nonce.AsSpan(),
                                                  aad.AsSpan(),
                                                  plaintext.AsSpan(),
                                                  ctBuf.AsSpan(),
                                                  tag.AsSpan());
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(tmpKey);
                        CryptographicOperations.ZeroMemory(aad);
                    }

                    int total = 1 + 8 + 4 + 4 + nonce.Length + keyBytes.Length + ctBuf.Length + tag.Length;
                    var buf = new byte[total];
                    int off = 0;
                    buf[off++] = op;
                    BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(off, 8), seq); off += 8;
                    BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(off, 4), keyBytes.Length); off += 4;
                    BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(off, 4), ctBuf.Length); off += 4;

                    nonce.CopyTo(buf.AsSpan(off, nonce.Length)); off += nonce.Length;
                    keyBytes.CopyTo(buf.AsSpan(off, keyBytes.Length)); off += keyBytes.Length;
                    ctBuf.CopyTo(buf.AsSpan(off, ctBuf.Length)); off += ctBuf.Length;
                    tag.CopyTo(buf.AsSpan(off, tag.Length)); off += tag.Length;

                    await stream.WriteAsync(buf, 0, buf.Length, cancellationToken).ConfigureAwait(false);
                }

                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }, cancellationToken).ConfigureAwait(false);

            // 3) Ricostruisci indice dal nuovo device
            var dekCopy = this.dek.ToManagedCopy();
            try
            {
                this.index.Clear();
                this.nextSeq = await RebuildIndexAsync(this.storeProvider, 
                                                       dekCopy, 
                                                       cancellationToken)
                                    .ConfigureAwait(false);
            }
            catch(Exception exc)
            {
                this.Logger?.LogDebug(exc, "Error during index rebuild after compaction");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dekCopy);
            }
        }


        public async ValueTask DisposeAsync()
        {
            dek.Dispose();
            await storeProvider.FlushAsync(true);
        }

        #region Internals

        //private AesGcm CreateGcm(out byte[] temporaryKey)
        //{ 
        //    temporaryKey = dek.ToManagedCopy();            
        //    return new (temporaryKey, temporaryKey.Length); 
        //}

      
        static async Task CopyHeaderAsync(IAppendOnlyStoreProvider storeProvider, 
                                          Stream destination, 
                                          CancellationToken cancellationToken = default)
        {
            // Read first 10 bytes to get headerLen            
            byte[] headerFixed = new byte[10];
            int read = await storeProvider.ReadAtAsync(0, 
                                                       headerFixed, 
                                                       cancellationToken)
                                          .ConfigureAwait(false);

            if (read != headerFixed.Length) 
                throw new InvalidDataException("Incomplete header");

            using BinaryWriter bw = new (destination, Encoding.UTF8, leaveOpen: true);
            bw.Write(headerFixed);

            int headerLen = BinaryPrimitives.ReadInt32LittleEndian(headerFixed.AsSpan(6, 4));
            byte[] payload = new byte[headerLen];

            read = await storeProvider.ReadAtAsync(headerFixed.Length, 
                                                   payload, 
                                                   cancellationToken)
                                      .ConfigureAwait(false);

            if (read != payload.Length) 
                throw new InvalidDataException("Incomplete header payload");

            bw.Write(payload);
        }

        static async Task<long> RebuildIndexAsync(IAppendOnlyStoreProvider storeProvider, 
                                                  byte[] dek, 
                                                  CancellationToken cancellationToken = default)
        {
            long pos = await HeaderEndOffsetAsync(storeProvider, cancellationToken).ConfigureAwait(false);
            long fileLen = await storeProvider.GetLengthAsync(cancellationToken).ConfigureAwait(false);
            var index = new Dictionary<string, IndexEntry>(StringComparer.Ordinal);
            long maxSeq = 0;

            // Read buffer
            byte[] buf = ArrayPool<byte>.Shared.Rent(1024 * 64);

            try
            {
                while (pos < fileLen)
                {
                    // leggi il minimo header record
                    int need = 1 + 8 + 4 + 4 + GCMNonceLen;
                    int got = await storeProvider.ReadAtAsync(pos, buf.AsMemory(0, need), cancellationToken).ConfigureAwait(false);
                    if (got < need) break;

                    int off = 0;
                    byte op = buf[off++];

                    long seq = BinaryPrimitives.ReadInt64LittleEndian(buf.AsSpan(off, 8)); 
                    off += 8;

                    int keyLen = BinaryPrimitives.ReadInt32LittleEndian(buf.AsSpan(off, 4)); 
                    off += 4;

                    int ctLen = BinaryPrimitives.ReadInt32LittleEndian(buf.AsSpan(off, 4)); 
                    off += 4 + GCMNonceLen;

                    // off += GCMNonceLen;

                    int total = 1 + 8 + 4 + 4 + GCMNonceLen + keyLen + ctLen + GCMTagLen;

                    if (total < 0 || total > 100_000_000) 
                        break;

                    // Read the entire record to recover the key (without decrypting)
                    var rec = ArrayPool<byte>.Shared.Rent(total);
                    try
                    {
                        got = await storeProvider.ReadAtAsync(pos, rec.AsMemory(0, total), cancellationToken).ConfigureAwait(false);
                        if (got != total) 
                            break;

                        int o = 1 + 8 + 4 + 4 + GCMNonceLen;
                        var keyBytes = rec.AsSpan(o, keyLen).ToArray();

                        var key = Encoding.UTF8.GetString(keyBytes);
                        var deleted = op == 1;
                        index[key] = new IndexEntry(seq, pos, total, deleted);
                        if (seq > maxSeq) maxSeq = seq;
                    }
                    finally 
                    { 
                        ArrayPool<byte>.Shared.Return(rec); 
                    }

                    pos += total;
                }
            }
            finally 
            { 
                ArrayPool<byte>.Shared.Return(buf); 
            }

            // Updated memory structure
            return maxSeq;
        }

        static async Task<long> HeaderEndOffsetAsync(IAppendOnlyStoreProvider storeProvider, 
                                                     CancellationToken cancellationToken = default)
        {
            byte[] hdr = new byte[4 + 1 + 1 + 4];
            int got = await storeProvider.ReadAtAsync(0, hdr, cancellationToken)
                                         .ConfigureAwait(false);

            if (got != hdr.Length) 
                throw new InvalidDataException("Incomplete header");

            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(hdr);

            if (magic != MagicNumber) 
                throw new InvalidDataException("Wrong MAGIC number");

            byte ver = hdr[4]; 

            if (ver != Version) 
                throw new NotSupportedException($"Versione {ver} non supportata");

            int headerLen = BinaryPrimitives.ReadInt32LittleEndian(hdr.AsSpan(6, 4));
            return hdr.Length + headerLen;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability",
                                                         "CA1416", 
                                                         Justification = "If not windows will throw an exception")]
        static void WriteHeader(Stream destination, 
                                byte[] dek, 
                                KeyProtectionMode mode, 
                                ReadOnlySpan<byte> passwordUtf8, 
                                IArgon2idParamsProvider? argonParametersProvider,
                                IAEADProvider aeadProvider,
                                IArgonKeyProvider? argonKeyProvider = null)
        {
            if (argonKeyProvider == null)
                argonKeyProvider = new ArgonKeyProvider();

            byte[] payload;
            using BinaryWriter bw = new (destination, Encoding.UTF8, leaveOpen: true);

            bw.Write(MagicNumber);
            bw.Write(Version);
            bw.Write((byte)mode);            

            switch (mode)
            {
                case KeyProtectionMode.PasswordArgon2id:
                    {
                        if (passwordUtf8.IsEmpty) 
                            throw new ArgumentException("Password is required for Argon2id");

                        TimeSpan timeTarget = TimeSpan.FromMilliseconds(500);
                        IArgon2idParamsProvider? currentArgonProvider = (argonParametersProvider ?? new CalibratingArgon2idParamsProvider(timeTarget));
                        Argon2idParams argon2IdParams = currentArgonProvider.GetParameters();
                        byte[] salt = MemoryBlockHelper.RandomBytes(16);
                        byte[] passwordTemp = passwordUtf8.ToArray();

                        byte[] kek = argonKeyProvider.DeriveKekArgon2id(passwordTemp, 
                                                       salt,
                                                       argon2IdParams.MemoryKiB,
                                                       argon2IdParams.Iterations,
                                                       argon2IdParams.Parallelism);
                        CryptographicOperations.ZeroMemory(passwordTemp);

                        byte[] nonce = MemoryBlockHelper.RandomBytes(GCMNonceLen);
                        byte[] encDek = new byte[dek.Length];
                        byte[] tag = new byte[GCMTagLen];

                        //using (AesGcm g = new (kek)) 
                        //g.Encrypt(nonce, dek, encDek, tag, ReadOnlySpan<byte>.Empty);

                        aeadProvider.Encrypt(kek, nonce, ReadOnlySpan<byte>.Empty, dek, encDek, tag);


                        CryptographicOperations.ZeroMemory(kek);

                        payload = new byte[2 + salt.Length + 4 + 4 + 4 + GCMNonceLen + encDek.Length + GCMTagLen];
                        Span<byte> span = payload.AsSpan();

                        BinaryPrimitives.WriteUInt16LittleEndian(span, (ushort)salt.Length); span = span[2..];
                        salt.CopyTo(span); span = span[salt.Length..];

                        BinaryPrimitives.WriteInt32LittleEndian(span, argon2IdParams.MemoryKiB); 
                        span = span[4..];

                        BinaryPrimitives.WriteInt32LittleEndian(span, argon2IdParams.Iterations); 
                        span = span[4..];

                        BinaryPrimitives.WriteInt32LittleEndian(span, argon2IdParams.Parallelism); 
                        span = span[4..];

                        nonce.CopyTo(span); 
                        span = span[GCMNonceLen..];

                        encDek.CopyTo(span); 
                        span = span[encDek.Length..];

                        tag.CopyTo(span);
                    }
                    break;

                case KeyProtectionMode.WindowsDPAPI:
                    {
                        if (OperatingSystem.IsWindows() == false)
                            throw new PlatformNotSupportedException("Windows DPAPI not supported on this platform.");
                        
                        byte[] enc = ProtectedData.Protect(dek, null, DataProtectionScope.CurrentUser);
                        payload = enc;
                    }
                    break;

                case KeyProtectionMode.PasswordPBKDF2:
                    {
                        if (passwordUtf8.IsEmpty) 
                            throw new ArgumentException("Password required for PBKDF2");

                        byte[] salt = MemoryBlockHelper.RandomBytes(16);
                        int iters = DefaultIteractions;

                        using Rfc2898DeriveBytes kdf = new (passwordUtf8.ToArray(), 
                                                            salt, 
                                                            iters, 
                                                            HashAlgorithmName.SHA256);
                        byte[] kek = kdf.GetBytes(32);
                        byte[] nonce = MemoryBlockHelper.RandomBytes(GCMNonceLen);
                        byte[] encDek = new byte[dek.Length];
                        byte[] tag = new byte[GCMTagLen];

                        // using (AesGcm aesGcm = new (kek)) 

                        // aesGcm.Encrypt(nonce, dek, encDek, tag, ReadOnlySpan<byte>.Empty);

                        aeadProvider.Encrypt(kek, nonce, ReadOnlySpan<byte>.Empty, dek, encDek, tag);

                        CryptographicOperations.ZeroMemory(kek);

                        payload = new byte[2 + salt.Length + 4 + GCMNonceLen + encDek.Length + GCMTagLen];

                        Span<byte> span = payload.AsSpan();

                        BinaryPrimitives.WriteUInt16LittleEndian(span, (ushort)salt.Length); 
                        span = span[2..];

                        salt.CopyTo(span); 
                        span = span[salt.Length..];

                        BinaryPrimitives.WriteInt32LittleEndian(span, iters); 
                        span = span[4..];

                        nonce.CopyTo(span); span = span[GCMNonceLen..];
                        encDek.CopyTo(span); span = span[encDek.Length..];
                        tag.CopyTo(span);
                    }
                    break;

                default:
                    throw new NotSupportedException("Protection mode not supported.");
            }            

            bw.Write(payload.Length);
            bw.Write(payload);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", 
                                                         "CA1416", 
                                                         Justification = "When not on Windows, an exception is thrown")]
        static async Task<(byte[] Dek, KeyProtectionMode Mode)> ReadHeaderAsync(IAppendOnlyStoreProvider storeProvider,
                                                                                IAEADProvider aeadProvider,
                                                                                KeyProtectionMode expected,
                                                                                byte[] passwordUTF8,
                                                                                IArgonKeyProvider? argonKeyProvider = null,
                                                                                CancellationToken cancellationToken = default)
        {
            byte[] fixedHdr = new byte[4 + 1 + 1 + 4];
            int got = await storeProvider.ReadAtAsync(0, fixedHdr, cancellationToken)
                               .ConfigureAwait(false);

            if (argonKeyProvider == null)
                argonKeyProvider = new ArgonKeyProvider();

            if (got != fixedHdr.Length) 
                throw new InvalidDataException("Incomplete header");

            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(fixedHdr);
            if (magic != MagicNumber) 
                throw new InvalidDataException("Wrong magic number");

            byte ver = fixedHdr[4]; 
            
            if (ver != Version) 
                throw new NotSupportedException($"Version {ver} not supported");

            KeyProtectionMode modeOnDisk = (KeyProtectionMode)fixedHdr[5];
            int headerLen = BinaryPrimitives.ReadInt32LittleEndian(fixedHdr.AsSpan(6, 4));

            byte[] payload = new byte[headerLen];

            got = await storeProvider.ReadAtAsync(fixedHdr.Length, 
                                                  payload, 
                                                  cancellationToken)
                                     .ConfigureAwait(false);

            if (got != payload.Length) 
                throw new InvalidDataException("Incomplete header payload");

            switch (modeOnDisk)
            {
                case KeyProtectionMode.PasswordArgon2id:
                    {
                        if (passwordUTF8.Length == 0)
                            throw new ArgumentException("Password required for Argon2id");

                        ArraySegment<byte> span = new(payload);
                        ushort saltLen = BinaryPrimitives.ReadUInt16LittleEndian(span);
                        span = span[2..];

                        byte[] salt = span[..saltLen].ToArray();
                        span = span[saltLen..];

                        int memKiB = BinaryPrimitives.ReadInt32LittleEndian(span);
                        span = span[4..];

                        int iters = BinaryPrimitives.ReadInt32LittleEndian(span);
                        span = span[4..];

                        int par = BinaryPrimitives.ReadInt32LittleEndian(span);
                        span = span[4..];

                        byte[] nonce = span[..GCMNonceLen].ToArray();
                        span = span[GCMNonceLen..];

                        int encDekLen = span.Count - GCMTagLen;
                        byte[] encDek = [.. span[..encDekLen]];
                        byte[] tag = [.. span[encDekLen..]];

                        byte[] pwdTmp = [.. passwordUTF8];
                        byte[] kek = argonKeyProvider.DeriveKekArgon2id(pwdTmp, 
                                                                        salt, 
                                                                        memKiB, 
                                                                        iters, 
                                                                        par);
                        CryptographicOperations.ZeroMemory(pwdTmp);

                        byte[] dek = new byte[encDek.Length];

                        try
                        {

                            aeadProvider.Decrypt(kek, nonce, ReadOnlySpan<byte>.Empty, encDek, tag, dek);

                            
                            //using AesGcm aesGcm = new (kek);
                            //aesGcm.Decrypt(nonce, 
                            //               encDek, 
                            //               tag, 
                            //               dek, 
                            //               ReadOnlySpan<byte>.Empty);
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(kek);
                        }

                        return (dek, modeOnDisk);
                    }

                case KeyProtectionMode.WindowsDPAPI:
                    {
                        if (OperatingSystem.IsWindows() == false)
                            throw new PlatformNotSupportedException("Windows DPAPI not supported on this platform.");

                        byte[] dek = ProtectedData.Unprotect(payload, 
                                                             null, 
                                                             DataProtectionScope.CurrentUser);
                        return (dek, modeOnDisk);
                    }

                case KeyProtectionMode.PasswordPBKDF2:
                    {
                        if (passwordUTF8.Length == 0)
                            throw new ArgumentException("Password richiesta per PBKDF2");

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

                        using Rfc2898DeriveBytes kdf = new ([.. passwordUTF8], 
                                                            salt, 
                                                            iters, 
                                                            HashAlgorithmName.SHA256);
                        byte[] kek = kdf.GetBytes(32);
                        byte[] dek = new byte[encDek.Length];
                        try 
                        {
                            aeadProvider.Decrypt(kek, nonce, ReadOnlySpan<byte>.Empty, encDek, tag, dek);
                            //using AesGcm aesGcm = new (kek); 
                            //aesGcm.Decrypt(nonce, 
                            //               encDek, 
                            //               tag, 
                            //               dek, 
                            //               ReadOnlySpan<byte>.Empty); 
                        }
                        finally 
                        { 
                            CryptographicOperations.ZeroMemory(kek); 
                        }
                        return (dek, modeOnDisk);
                    }

                default:
                    throw new NotSupportedException("Protection mode not supported.");
            }            
        }       

        #endregion
    }

}
