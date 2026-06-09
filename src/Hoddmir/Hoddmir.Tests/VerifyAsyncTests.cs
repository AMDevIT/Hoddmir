using Hoddmir.BouncyCastle.Encryption.AEAD;
using Hoddmir.Core.Encryption.AEAD;
using Hoddmir.Core.Keys;
using Hoddmir.Storage;
using Hoddmir.Storage.Providers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;

namespace Hoddmir.Tests;

[TestClass]
public sealed class VerifyAsyncTests
{
    // ── Infrastructure ───────────────────────────────────────────────────────

    private static readonly byte[] Password = Encoding.UTF8.GetBytes("test-password");
    private static readonly IArgon2idParamsProvider FastArgon = new FixedArgon2idParamsProvider(new Argon2idParams(32 * 1024, 2, 2));

    private static Task<EncryptedEntryStore> CreateStoreAsync(MemoryAppendOnlyStoreProvider ms, IAEADProvider aead) =>
        EncryptedEntryStore.Configure()
            .WithPassword(Password)
            .WithArgon2id(FastArgon)
            .WithAead(aead)
            .OpenAsync(ms, ms);

    // ── Happy path ───────────────────────────────────────────────────────────

    /// <summary>Empty store (header only) must report IsHealthy with zero records.</summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task EmptyStore_IsHealthy(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        var result = await store.VerifyAsync();

        Assert.IsTrue(result.IsHealthy);
        Assert.AreEqual(0, result.TotalRecords);
        Assert.AreEqual(0, result.ValidRecords);
        Assert.AreEqual(0, result.CorruptedRecords);
        Assert.AreEqual(0, result.TruncatedRecords);
        Assert.AreEqual(0, result.CorruptedKeys.Count);
        Assert.AreEqual(0, result.TruncatedOffsets.Count);
    }

    /// <summary>All Put records must verify cleanly.</summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task PutRecords_AllVerify(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("alpha", Encoding.UTF8.GetBytes("AAA"));
        await store.PutAsync("beta", Encoding.UTF8.GetBytes("BBB"));
        await store.PutAsync("gamma", Encoding.UTF8.GetBytes("CCC"));

        var result = await store.VerifyAsync();

        Assert.IsTrue(result.IsHealthy);
        Assert.AreEqual(3, result.TotalRecords);
        Assert.AreEqual(3, result.ValidRecords);
        Assert.AreEqual(0, result.CorruptedRecords);
    }

    /// <summary>Delete tombstones are also records and must verify cleanly.</summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task DeleteTombstones_AlsoVerify(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("a", Encoding.UTF8.GetBytes("data"));
        await store.DeleteAsync("a");
        await store.PutAsync("b", Encoding.UTF8.GetBytes("keep"));

        // 3 records: Put(a), Delete(a), Put(b)
        var result = await store.VerifyAsync();

        Assert.IsTrue(result.IsHealthy);
        Assert.AreEqual(3, result.TotalRecords);
        Assert.AreEqual(3, result.ValidRecords);
    }

    /// <summary>Store with overwritten key (two Put records for same key) must fully verify.</summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task OverwrittenKey_BothRecordsVerify(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("k", Encoding.UTF8.GetBytes("v1"));
        await store.PutAsync("k", Encoding.UTF8.GetBytes("v2"));

        // 2 records on disk even though the index only keeps the last
        var result = await store.VerifyAsync();

        Assert.IsTrue(result.IsHealthy);
        Assert.AreEqual(2, result.TotalRecords);
        Assert.AreEqual(2, result.ValidRecords);
    }

    /// <summary>Store verified after CompactAsync must still be healthy.</summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task AfterCompact_StoreIsHealthy(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("keep", Encoding.UTF8.GetBytes("live"));
        await store.PutAsync("gone", Encoding.UTF8.GetBytes("dead"));
        await store.DeleteAsync("gone");
        await store.CompactAsync();

        var result = await store.VerifyAsync();

        Assert.IsTrue(result.IsHealthy);
        Assert.AreEqual(1, result.TotalRecords);
        Assert.AreEqual(1, result.ValidRecords);
    }

    /// <summary>Store verified after RotateDekAsync must still be healthy with all records intact.</summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task AfterRotateDek_StoreIsHealthy(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("x", Encoding.UTF8.GetBytes("value-x"));
        await store.PutAsync("y", Encoding.UTF8.GetBytes("value-y"));

        await store.RotateDekAsync(Password);

        var result = await store.VerifyAsync();

        Assert.IsTrue(result.IsHealthy);
        Assert.AreEqual(2, result.TotalRecords);
        Assert.AreEqual(2, result.ValidRecords);
    }

    // ── Corruption detection ─────────────────────────────────────────────────

    /// <summary>
    /// Flipping a single bit in the ciphertext of one record must be detected
    /// as a corrupted record, while the others remain valid.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task CorruptedCiphertext_DetectedAsCorrupted(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("ok1", Encoding.UTF8.GetBytes("good"));
        await store.PutAsync("corrupt", Encoding.UTF8.GetBytes("this will be tampered"));
        await store.PutAsync("ok2", Encoding.UTF8.GetBytes("also good"));

        // Tamper: flip one byte in the ciphertext of record 2
        FlipByteInRecord(ms, recordIndex: 1, byteOffsetInCt: 0);

        var result = await store.VerifyAsync();

        Assert.IsFalse(result.IsHealthy);
        Assert.AreEqual(3, result.TotalRecords);
        Assert.AreEqual(2, result.ValidRecords);
        Assert.AreEqual(1, result.CorruptedRecords);
        Assert.AreEqual(0, result.TruncatedRecords);
        Assert.IsTrue(result.CorruptedKeys.Contains("corrupt"));
    }

    /// <summary>Flipping a bit in the authentication tag must be detected as corruption.</summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task CorruptedTag_DetectedAsCorrupted(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("victim", Encoding.UTF8.GetBytes("data"));

        // Tamper: flip the last byte of the record (part of the tag)
        FlipLastByteOfRecord(ms, recordIndex: 0);

        var result = await store.VerifyAsync();

        Assert.IsFalse(result.IsHealthy);
        Assert.AreEqual(1, result.CorruptedRecords);
        Assert.IsTrue(result.CorruptedKeys.Contains("victim"));
    }

    /// <summary>
    /// Corrupting multiple records must report all of them individually.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task MultipleCorruptedRecords_AllDetected(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("r0", Encoding.UTF8.GetBytes("zero"));
        await store.PutAsync("r1", Encoding.UTF8.GetBytes("one"));
        await store.PutAsync("r2", Encoding.UTF8.GetBytes("two"));
        await store.PutAsync("r3", Encoding.UTF8.GetBytes("three"));

        FlipByteInRecord(ms, recordIndex: 1, byteOffsetInCt: 2);
        FlipByteInRecord(ms, recordIndex: 3, byteOffsetInCt: 0);

        var result = await store.VerifyAsync();

        Assert.IsFalse(result.IsHealthy);
        Assert.AreEqual(4, result.TotalRecords);
        Assert.AreEqual(2, result.ValidRecords);
        Assert.AreEqual(2, result.CorruptedRecords);
        Assert.IsTrue(result.CorruptedKeys.Contains("r1"));
        Assert.IsTrue(result.CorruptedKeys.Contains("r3"));
        Assert.IsFalse(result.CorruptedKeys.Contains("r0"));
        Assert.IsFalse(result.CorruptedKeys.Contains("r2"));
    }

    // ── Truncation detection ─────────────────────────────────────────────────

    /// <summary>
    /// A file truncated in the middle of a record body must be reported as truncated,
    /// with previously valid records counted correctly.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task TruncatedRecordBody_Detected(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("first", Encoding.UTF8.GetBytes("ok"));
        await store.PutAsync("second", Encoding.UTF8.GetBytes("also ok"));
        await store.PutAsync("third", Encoding.UTF8.GetBytes("this will be cut"));

        // Truncate 20 bytes off the end — cuts into the last record body
        TruncateStore(ms, bytesToRemove: 20);

        var result = await store.VerifyAsync();

        Assert.IsFalse(result.IsHealthy);
        Assert.AreEqual(1, result.TruncatedRecords);
        Assert.AreEqual(1, result.TruncatedOffsets.Count);
        // The first two records must still be valid
        Assert.AreEqual(2, result.ValidRecords);
    }

    /// <summary>
    /// A file truncated in the middle of a record prefix (fixed header) must also be detected.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task TruncatedRecordPrefix_Detected(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("only", Encoding.UTF8.GetBytes("data"));

        // Truncate enough to cut into the fixed prefix of the record (17 bytes)
        TruncateStore(ms, bytesToRemove: 5);

        var result = await store.VerifyAsync();

        Assert.IsFalse(result.IsHealthy);
        Assert.AreEqual(1, result.TruncatedRecords);
        Assert.AreEqual(0, result.ValidRecords);
        Assert.AreEqual(0, result.CorruptedRecords);
    }

    // ── VerifyResult helpers ─────────────────────────────────────────────────

    /// <summary>IsHealthy must be true only when both corrupted and truncated are zero.</summary>
    [TestMethod]
    public void VerifyResult_IsHealthy_OnlyWhenBothZero()
    {
        var healthy = new VerifyResult(5, 5, 0, 0, [], []);
        Assert.IsTrue(healthy.IsHealthy);

        var withCorrupted = new VerifyResult(5, 4, 1, 0, ["k"], []);
        Assert.IsFalse(withCorrupted.IsHealthy);

        var withTruncated = new VerifyResult(5, 4, 0, 1, [], [100L]);
        Assert.IsFalse(withTruncated.IsHealthy);

        var withBoth = new VerifyResult(5, 3, 1, 1, ["k"], [100L]);
        Assert.IsFalse(withBoth.IsHealthy);
    }

    /// <summary>ToString must include counts for unhealthy stores.</summary>
    [TestMethod]
    public void VerifyResult_ToString_HealthyAndUnhealthy()
    {
        var healthy = new VerifyResult(3, 3, 0, 0, [], []);
        StringAssert.Contains(healthy.ToString(), "healthy");

        var unhealthy = new VerifyResult(3, 1, 1, 1, ["bad"], [42L]);
        StringAssert.Contains(unhealthy.ToString(), "UNHEALTHY");
        StringAssert.Contains(unhealthy.ToString(), "1 corrupted");
        StringAssert.Contains(unhealthy.ToString(), "1 truncated");
    }

    // ── Providers ────────────────────────────────────────────────────────────

    private static IEnumerable<object[]> Providers() =>
    [
        [new AesGcmProvider()],
        [new AesCtrHmacSha256Provider()],
        [new ChaCha20Poly1305Provider()],
    ];

    // ── Tamper helpers ───────────────────────────────────────────────────────

    private const int FixedHdrSize = 4 + 1 + 1 + 1 + 4; // MAGIC+VER+KeyMode+AeadId+HeaderLen
    private const int RecordFixedPrefix = 1 + 8 + 4 + 4;      // Op+Seq+KeyLen+CtLen
    private const int NonceLen = 12;
    private const int TagLen = 16;

    /// <summary>
    /// Computes the file offset of the ciphertext start for the given zero-based record index,
    /// then flips the byte at <paramref name="byteOffsetInCt"/> within that ciphertext.
    /// </summary>
    private static void FlipByteInRecord(MemoryAppendOnlyStoreProvider ms,
                                         int recordIndex,
                                         int byteOffsetInCt)
    {
        long pos = GetRecordOffset(ms, recordIndex);

        // Read the fixed prefix to find keyLen and ctLen
        byte[] prefix = new byte[RecordFixedPrefix];
        ms.ReadAtAsync(pos, prefix).GetAwaiter().GetResult();
        int keyLen = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(9, 4));
        int ctLen = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(13, 4));

        Assert.IsTrue(byteOffsetInCt < ctLen,
            $"byteOffsetInCt ({byteOffsetInCt}) must be < ctLen ({ctLen})");

        long ctStart = pos + RecordFixedPrefix + NonceLen + keyLen;
        long flipAt = ctStart + byteOffsetInCt;

        PatchByte(ms, flipAt, b => (byte)(b ^ 0xFF));
    }

    /// <summary>Flips the very last byte of the specified record (part of the tag).</summary>
    private static void FlipLastByteOfRecord(MemoryAppendOnlyStoreProvider ms,
                                             int recordIndex)
    {
        long pos = GetRecordOffset(ms, recordIndex);

        byte[] prefix = new byte[RecordFixedPrefix];
        ms.ReadAtAsync(pos, prefix).GetAwaiter().GetResult();
        int keyLen = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(9, 4));
        int ctLen = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(13, 4));

        long recordEnd = pos + RecordFixedPrefix + NonceLen + keyLen + ctLen + TagLen;
        PatchByte(ms, recordEnd - 1, b => (byte)(b ^ 0xFF));
    }

    /// <summary>
    /// Walks the record list (skipping the file header) and returns the file offset
    /// of the record at the given zero-based <paramref name="index"/>.
    /// </summary>
    private static long GetRecordOffset(MemoryAppendOnlyStoreProvider ms, int index)
    {
        byte[] hdr = new byte[FixedHdrSize];
        ms.ReadAtAsync(0, hdr).GetAwaiter().GetResult();
        int hdrPayloadLen = BinaryPrimitives.ReadInt32LittleEndian(hdr.AsSpan(FixedHdrSize - 4, 4));
        long pos = FixedHdrSize + hdrPayloadLen;

        for (int i = 0; i < index; i++)
        {
            byte[] prefix = new byte[RecordFixedPrefix];
            ms.ReadAtAsync(pos, prefix).GetAwaiter().GetResult();
            int keyLen = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(9, 4));
            int ctLen = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(13, 4));
            pos += RecordFixedPrefix + NonceLen + keyLen + ctLen + TagLen;
        }

        return pos;
    }

    /// <summary>
    /// Reads the byte at <paramref name="offset"/>, applies <paramref name="patch"/>,
    /// and writes it back using ReplaceWithAsync to stay within the provider contract.
    /// </summary>
    private static void PatchByte(MemoryAppendOnlyStoreProvider ms,
                                  long offset,
                                  Func<byte, byte> patch)
    {
        byte[] oneByte = new byte[1];
        ms.ReadAtAsync(offset, oneByte).GetAwaiter().GetResult();
        oneByte[0] = patch(oneByte[0]);

        ms.ReplaceWithAsync(async stream =>
        {
            long len = await ms.GetLengthAsync().ConfigureAwait(false);
            byte[] all = new byte[len];
            await ms.ReadAtAsync(0, all).ConfigureAwait(false);
            all[offset] = oneByte[0];
            await stream.WriteAsync(all).ConfigureAwait(false);
        }).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Truncates the store by removing the last <paramref name="bytesToRemove"/> bytes.
    /// </summary>
    private static void TruncateStore(MemoryAppendOnlyStoreProvider ms, int bytesToRemove)
    {
        ms.ReplaceWithAsync(async stream =>
        {
            long len = await ms.GetLengthAsync().ConfigureAwait(false);
            byte[] all = new byte[len];
            await ms.ReadAtAsync(0, all).ConfigureAwait(false);
            int newLen = Math.Max(0, all.Length - bytesToRemove);
            await stream.WriteAsync(all.AsMemory(0, newLen)).ConfigureAwait(false);
        }).GetAwaiter().GetResult();
    }
}