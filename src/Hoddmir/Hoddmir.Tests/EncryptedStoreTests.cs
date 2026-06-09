using Hoddmir.BouncyCastle.Encryption.AEAD;
using Hoddmir.Core.Encryption.AEAD;
using Hoddmir.Core.Keys;
using Hoddmir.Storage;
using Hoddmir.Storage.Providers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Hoddmir.Tests;

[TestClass]
public sealed class EncryptedStoreTests
{
    private static readonly byte[] Password = Encoding.UTF8.GetBytes("test-password");

    // Fast fixed Argon2id params to keep tests quick
    private static readonly IArgon2idParamsProvider FastArgon = new FixedArgon2idParamsProvider(new Argon2idParams(32 * 1024, 2, 2));

    private static Task<EncryptedEntryStore> CreateStoreAsync(MemoryAppendOnlyStoreProvider ms, IAEADProvider aead) =>
        EncryptedEntryStore.Configure()
            .WithPassword(Password)
            .WithArgon2id(FastArgon)
            .WithAead(aead)
            .OpenAsync(ms, ms);

    // ── Round-trip ──────────────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task PutGetRoundtrip(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms    = new MemoryAppendOnlyStoreProvider();
        var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("user:42", Encoding.UTF8.GetBytes("hello, world!"));
        byte[]? got = await store.GetAsync("user:42");

        Assert.IsNotNull(got);
        Assert.AreEqual("hello, world!", Encoding.UTF8.GetString(got!));
        await store.DisposeAsync();
    }

    // ── Delete ───────────────────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task DeleteRemovesEntry(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms    = new MemoryAppendOnlyStoreProvider();
        var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("a", Encoding.UTF8.GetBytes("A"));
        await store.PutAsync("b", Encoding.UTF8.GetBytes("B"));
        await store.DeleteAsync("a");

        Assert.IsNull(await store.GetAsync("a"), "GetAsync('a') should be null after delete");
        Assert.IsNotNull(await store.GetAsync("b"));
        CollectionAssert.DoesNotContain((System.Collections.ICollection)store.ListIds(), "a");
        CollectionAssert.Contains((System.Collections.ICollection)store.ListIds(), "b");
        await store.DisposeAsync();
    }

    // ── Compact ──────────────────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task CompactShrinksStore(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms    = new MemoryAppendOnlyStoreProvider();
        var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("keep", Encoding.UTF8.GetBytes("live"));
        await store.PutAsync("gone", Encoding.UTF8.GetBytes("dead"));
        await store.DeleteAsync("gone");

        long before = await ms.GetLengthAsync();
        await store.CompactAsync();
        long after  = await ms.GetLengthAsync();

        Assert.IsTrue(after <= before, $"Expected length to shrink, got {before} → {after}");
        Assert.AreEqual("live", Encoding.UTF8.GetString((await store.GetAsync("keep"))!));
        Assert.IsNull(await store.GetAsync("gone"));
        await store.DisposeAsync();
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task PutOverwriteLastWinsAfterCompact(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms    = new MemoryAppendOnlyStoreProvider();
        var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("k", Encoding.UTF8.GetBytes("v1"));
        await store.PutAsync("k", Encoding.UTF8.GetBytes("v2"));
        Assert.AreEqual("v2", Encoding.UTF8.GetString((await store.GetAsync("k"))!));

        await store.CompactAsync();
        Assert.AreEqual("v2", Encoding.UTF8.GetString((await store.GetAsync("k"))!));
        await store.DisposeAsync();
    }

    // ── Persist & reopen ─────────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task ReopenRestoresData(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();

        await using (var store = await CreateStoreAsync(ms, aead))
        {
            await store.PutAsync("x", Encoding.UTF8.GetBytes("persistent"));
        }

        // Reopen with the same backing store
        await using var store2 = await CreateStoreAsync(ms, aead);
        var got = await store2.GetAsync("x");
        Assert.IsNotNull(got);
        Assert.AreEqual("persistent", Encoding.UTF8.GetString(got!));
    }

    // ── Wrong AEAD provider on reopen ────────────────────────────────────────

    [TestMethod]
    public async Task ReopenWithWrongAeadThrows()
    {
        var ms = new MemoryAppendOnlyStoreProvider();
        await using (var store = await CreateStoreAsync(ms, new AesCtrHmacSha256Provider()))
        {
            await store.PutAsync("x", Encoding.UTF8.GetBytes("data"));
        }

        // Try to open with a different provider → InvalidOperationException
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(async () =>
            await CreateStoreAsync(ms, new ChaCha20Poly1305Provider()));
    }

    // ── Nonce uniqueness (fix #1) ─────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task NonceUniquenessAcrossWritesAndStores(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");

        const int Writes             = 50;
        const int RecordFixedPrefix  = 1 + 8 + 4 + 4;  // Op+Seq+KeyLen+CtLen
        const int NonceLen           = 12;
        const int TagLen             = 16;
        const int FixedHdrSize       = 4 + 1 + 1 + 1 + 4; // MAGIC+VER+KeyMode+AeadId+HeaderLen

        async Task<List<byte[]>> CollectNonces(MemoryAppendOnlyStoreProvider ms)
        {
            var store = await CreateStoreAsync(ms, aead);
            for (int i = 0; i < Writes; i++)
                await store.PutAsync($"k{i}", Encoding.UTF8.GetBytes($"v{i}"));
            await store.DisposeAsync();

            // Skip header, then walk records
            byte[] hdr = new byte[FixedHdrSize];
            await ms.ReadAtAsync(0, hdr);
            int hdrPayloadLen = BinaryPrimitives.ReadInt32LittleEndian(hdr.AsSpan(FixedHdrSize - 4, 4));
            long pos   = FixedHdrSize + hdrPayloadLen;
            long total = await ms.GetLengthAsync();

            var nonces = new List<byte[]>();
            byte[] prefix = new byte[RecordFixedPrefix];
            while (pos < total)
            {
                await ms.ReadAtAsync(pos, prefix);
                int keyLen = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(9, 4));
                int ctLen  = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(13, 4));
                byte[] n   = new byte[NonceLen];
                await ms.ReadAtAsync(pos + RecordFixedPrefix, n);
                nonces.Add(n);
                pos += RecordFixedPrefix + NonceLen + keyLen + ctLen + TagLen;
            }
            return nonces;
        }

        var ms1 = new MemoryAppendOnlyStoreProvider();
        var ms2 = new MemoryAppendOnlyStoreProvider();

        var nonces1 = await CollectNonces(ms1);
        var nonces2 = await CollectNonces(ms2);

        var set1 = nonces1.Select(n => Convert.ToHexString(n)).ToHashSet();
        var set2 = nonces2.Select(n => Convert.ToHexString(n)).ToHashSet();

        Assert.AreEqual(Writes, set1.Count, "Store 1: duplicate nonce detected — nonce reuse!");
        Assert.AreEqual(Writes, set2.Count, "Store 2: duplicate nonce detected — nonce reuse!");
        Assert.AreEqual(0, set1.Intersect(set2).Count(),
                        "Stores share at least one nonce — nonce prefix not unique per store!");
    }

    // ── Key rotation (#3) ────────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task RotateDek_DataSurvivesRotation(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms    = new MemoryAppendOnlyStoreProvider();
        var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("a", Encoding.UTF8.GetBytes("alpha"));
        await store.PutAsync("b", Encoding.UTF8.GetBytes("beta"));
        await store.DeleteAsync("a");

        await store.RotateDekAsync(Password);

        // All live data must survive with correct values
        Assert.IsNull(await store.GetAsync("a"),  "Deleted entry should still be absent after rotation");
        var b = await store.GetAsync("b");
        Assert.IsNotNull(b);
        Assert.AreEqual("beta", Encoding.UTF8.GetString(b!));

        await store.DisposeAsync();
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task RotateDek_ReopenAfterRotationWorks(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms    = new MemoryAppendOnlyStoreProvider();
        var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("x", Encoding.UTF8.GetBytes("original"));

        byte[] newPassword = Encoding.UTF8.GetBytes("new-password");
        await store.RotateDekAsync(Password, newPasswordUtf8: newPassword);
        await store.DisposeAsync();

        // Reopen with NEW password — must succeed
        var store2 = await EncryptedEntryStore.Configure()
            .WithPassword(newPassword)
            .WithArgon2id(FastArgon)
            .WithAead(aead)
            .OpenAsync(ms, ms);

        var got = await store2.GetAsync("x");
        Assert.IsNotNull(got);
        Assert.AreEqual("original", Encoding.UTF8.GetString(got!));
        await store2.DisposeAsync();
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task RotateDek_OldPasswordFailsAfterRotation(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms    = new MemoryAppendOnlyStoreProvider();
        var store = await CreateStoreAsync(ms, aead);
        await store.PutAsync("k", Encoding.UTF8.GetBytes("v"));

        byte[] newPassword = Encoding.UTF8.GetBytes("new-password");
        await store.RotateDekAsync(Password, newPasswordUtf8: newPassword);
        await store.DisposeAsync();

        // Reopen with OLD password — must fail
        await Assert.ThrowsExceptionAsync<CryptographicException>(async () => await EncryptedEntryStore.Configure()
                                                                                                       .WithPassword(Password)
                                                                                                       .WithArgon2id(FastArgon)
                                                                                                       .WithAead(aead)
                                                                                                       .OpenAsync(ms, ms));
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task RotateDek_WrongCurrentPasswordThrows(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms    = new MemoryAppendOnlyStoreProvider();
        var store = await CreateStoreAsync(ms, aead);
        await store.PutAsync("k", Encoding.UTF8.GetBytes("v"));

        byte[] wrongPassword = Encoding.UTF8.GetBytes("wrong-password");

        await Assert.ThrowsExceptionAsync<CryptographicException>(async () =>
            await store.RotateDekAsync(wrongPassword));

        // Store must still be readable with original password after the failed rotation
        var got = await store.GetAsync("k");
        Assert.IsNotNull(got);
        Assert.AreEqual("v", Encoding.UTF8.GetString(got!));

        await store.DisposeAsync();
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task RotateDek_NoncePrefixChanges(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");

        const int FixedHdrSize      = 4 + 1 + 1 + 1 + 4;
        const int NoncePrefixLen    = 8;

        async Task<byte[]> ReadNoncePrefix(MemoryAppendOnlyStoreProvider ms)
        {
            byte[] hdr = new byte[FixedHdrSize];
            await ms.ReadAtAsync(0, hdr);
            int hdrPayloadLen = BinaryPrimitives.ReadInt32LittleEndian(hdr.AsSpan(FixedHdrSize - 4, 4));
            // NoncePrefix is the last 8 bytes of the header payload
            byte[] prefix = new byte[NoncePrefixLen];
            await ms.ReadAtAsync(FixedHdrSize + hdrPayloadLen - NoncePrefixLen, prefix);
            return prefix;
        }

        var ms    = new MemoryAppendOnlyStoreProvider();
        var store = await CreateStoreAsync(ms, aead);
        await store.PutAsync("k", Encoding.UTF8.GetBytes("v"));

        byte[] prefixBefore = await ReadNoncePrefix(ms);
        await store.RotateDekAsync(Password);
        byte[] prefixAfter = await ReadNoncePrefix(ms);

        CollectionAssert.AreNotEqual(prefixBefore, prefixAfter,
            "NoncePrefix must change after DEK rotation.");

        await store.DisposeAsync();
    }

    #region Providers

    private static IEnumerable<object[]> Providers() =>
    [
        [new AesGcmProvider()],
        [new AesCtrHmacSha256Provider()],
        [new ChaCha20Poly1305Provider()],
    ];

    #endregion
}
