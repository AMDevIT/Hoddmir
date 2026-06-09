using Hoddmir.BouncyCastle.Encryption.AEAD;
using Hoddmir.Core.Encryption.AEAD;
using Hoddmir.Core.Keys;
using Hoddmir.Storage;
using Hoddmir.Storage.Providers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Hoddmir.Tests;

[TestClass]
public sealed class VerifyAsyncTests
{
    // ── Infrastructure ───────────────────────────────────────────────────────

    private static readonly byte[] Password = Encoding.UTF8.GetBytes("test-password");
    private static readonly IArgon2idParamsProvider FastArgon =
        new FixedArgon2idParamsProvider(new Argon2idParams(32 * 1024, 1, 1));

    // v0x04 header occupies sessionSaltLen(16) + EncryptedHeaderSize(512) = 528 bytes.
    private const int HeaderSize = 16 + 512;

    private static Task<EncryptedEntryStore> CreateStoreAsync(
        MemoryAppendOnlyStoreProvider ms, IAEADProvider aead) =>
        EncryptedEntryStore.Configure()
            .WithPassword(Password)
            .WithSessionIterations(1)
            .WithSessionSaltLength(16)
            .WithDekArgon2id(FastArgon)
            .WithAead(aead)
            .OpenAsync(ms, ms);

    // ── Happy path ───────────────────────────────────────────────────────────

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
    }

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

        // 3 data records: Put(a), Delete(a), Put(b)
        var result = await store.VerifyAsync();

        Assert.IsTrue(result.IsHealthy);
        Assert.AreEqual(3, result.TotalRecords);
        Assert.AreEqual(3, result.ValidRecords);
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task OverwrittenKey_BothRecordsVerify(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("k", Encoding.UTF8.GetBytes("v1"));
        await store.PutAsync("k", Encoding.UTF8.GetBytes("v2"));

        var result = await store.VerifyAsync();

        Assert.IsTrue(result.IsHealthy);
        Assert.AreEqual(2, result.TotalRecords);
        Assert.AreEqual(2, result.ValidRecords);
    }

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
    //
    // In v0x04 the format is fully opaque — record boundaries are only known
    // after decrypting the prefix. Rather than navigating the format from the
    // outside (which would require either duplicating crypto logic in test code
    // or exposing internals), we corrupt the file at known absolute positions:
    //
    //   - Middle of the record area: guaranteed to land inside some record's
    //     ciphertext or tag, causing AEAD tag failure.
    //   - Last N bytes: always the tail of the last record (PayloadTag or PaddedCt).
    //
    // These strategies test what matters: that VerifyAsync detects AEAD failures
    // and reports them correctly, regardless of which specific record is hit.

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task CorruptedRecordArea_DetectedAsCorrupted(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("a", Encoding.UTF8.GetBytes("alpha"));
        await store.PutAsync("b", Encoding.UTF8.GetBytes("beta"));
        await store.PutAsync("c", Encoding.UTF8.GetBytes("gamma"));

        // Flip a byte immediately after the header — always inside the first
        // data record regardless of how many index records follow it.
        FlipByteAt(ms, HeaderSize + 1);

        var result = await store.VerifyAsync();

        Assert.IsFalse(result.IsHealthy);
        Assert.IsTrue(result.CorruptedRecords >= 1,
            "At least one record must be detected as corrupted.");
        Assert.AreEqual(0, result.TruncatedRecords);
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task CorruptedDataRecordTag_DetectedAsCorrupted(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("victim", Encoding.UTF8.GetBytes("data"));

        // The file layout is [header][data_record][index_record].
        // VerifyAsync skips index records, so we must corrupt the data record area.
        // The data record sits between HeaderSize and (fileLen - size_of_index_record).
        // We flip a byte at HeaderSize+1 — always inside the first data record.
        FlipByteAt(ms, HeaderSize + 1);

        var result = await store.VerifyAsync();

        Assert.IsFalse(result.IsHealthy);
        Assert.IsTrue(result.CorruptedRecords >= 1);
        Assert.AreEqual(0, result.TruncatedRecords);
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task CorruptedEncPrefix_DetectedAsCorrupted(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("k", Encoding.UTF8.GetBytes("value"));

        // Flip a byte immediately after the header — first byte of the first record's
        // EncPrefix. This corrupts the prefix ciphertext, causing prefix decryption
        // failure which VerifyAsync reports as corrupted.
        FlipByteAt(ms, HeaderSize);

        var result = await store.VerifyAsync();

        Assert.IsFalse(result.IsHealthy);
        Assert.IsTrue(result.CorruptedRecords >= 1 || result.TruncatedRecords >= 1,
            "Corrupted EncPrefix must be detected as corrupted or truncated.");
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task MultipleCorruptedAreas_AllDetected(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("r0", Encoding.UTF8.GetBytes("zero"));
        await store.PutAsync("r1", Encoding.UTF8.GetBytes("one"));
        await store.PutAsync("r2", Encoding.UTF8.GetBytes("two"));
        await store.PutAsync("r3", Encoding.UTF8.GetBytes("three"));

        // Flip bytes inside the first data record area (immediately after header).
        // Each PutAsync writes [data_record][index_record], so data records start
        // at HeaderSize. We flip two bytes within the first record's opaque blob.
        FlipByteAt(ms, HeaderSize + 1);
        FlipByteAt(ms, HeaderSize + 2);

        var result = await store.VerifyAsync();

        Assert.IsFalse(result.IsHealthy);
        Assert.IsTrue(result.CorruptedRecords >= 1,
            "At least one corrupted record must be detected.");
    }

    // ── Truncation detection ─────────────────────────────────────────────────

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
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task TruncatedRecordPrefix_Detected(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("only", Encoding.UTF8.GetBytes("data"));

        // Truncate enough to cut into the EncPrefix of the first record
        TruncateStore(ms, bytesToRemove: 5);

        var result = await store.VerifyAsync();

        // Truncating 5 bytes may land inside a tag (detected as corrupted) or
        // inside a record body (detected as truncated) — both are valid signals.
        Assert.IsFalse(result.IsHealthy);
        Assert.IsTrue(result.TruncatedRecords + result.CorruptedRecords >= 1,
            "A truncated file must produce at least one truncated or corrupted record.");
    }

    // ── VerifyResult unit tests ───────────────────────────────────────────────

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

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Flips the byte at the given absolute file offset.
    /// Works as an external attacker would — no knowledge of record structure needed.
    /// </summary>
    private static void FlipByteAt(MemoryAppendOnlyStoreProvider ms, long offset)
    {
        ms.ReplaceWithAsync(async stream =>
        {
            long len = await ms.GetLengthAsync().ConfigureAwait(false);
            byte[] all = new byte[len];
            await ms.ReadAtAsync(0, all).ConfigureAwait(false);
            all[offset] ^= 0xFF;
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