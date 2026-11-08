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
public sealed class EncryptedStoreTests
{
    // ── Infrastructure ───────────────────────────────────────────────────────

    private static readonly byte[] Password = Encoding.UTF8.GetBytes("test-password");

    // Fast fixed Argon2id params for both session KEK and DEK to keep tests quick.
    // Session KEK: hardcoded SessionMemKiB=64MiB in the store — we only control iterations.
    // DEK: overridden via WithDekArgon2id.
    private static readonly IArgon2idParamsProvider FastDekArgon =
        new FixedArgon2idParamsProvider(new Argon2idParams(32 * 1024, 1, 1));

    /// <summary>Opens a test store with the given backend and reduced KDF parameters.</summary>
    private static Task<EncryptedEntryStore> CreateStoreAsync<TBackend>(TBackend backend,
                                                                        IAEADProvider aead,
                                                                        byte[]? password = null,
                                                                        int sessionIters = 1,
                                                                        int sessionSaltLen = 16)
        where TBackend : IAppendOnlyStoreProvider, IAtomicReplace =>
        EncryptedEntryStore.Configure()
            .WithPassword(password ?? Password)
            .WithSessionIterations(sessionIters)
            .WithSessionSaltLength(sessionSaltLen)
            .WithDekArgon2id(FastDekArgon)
            .WithAead(aead)
            .OpenAsync(backend, backend);

    // ── Round-trip ───────────────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task PutGetRoundtrip(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("user:42", Encoding.UTF8.GetBytes("hello, world!"));
        byte[]? got = await store.GetAsync("user:42");

        Assert.IsNotNull(got);
        Assert.AreEqual("hello, world!", Encoding.UTF8.GetString(got!));
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task PutGetRoundtrip_LargeValue(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        byte[] large = new byte[64 * 1024];
        RandomNumberGenerator.Fill(large);

        await store.PutAsync("big", large);
        byte[]? got = await store.GetAsync("big");

        Assert.IsNotNull(got);
        CollectionAssert.AreEqual(large, got);
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task PutGetRoundtrip_EmptyValue(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("empty", ReadOnlyMemory<byte>.Empty);
        byte[]? got = await store.GetAsync("empty");

        Assert.IsNotNull(got);
        Assert.AreEqual(0, got!.Length);
    }

    // ── Delete ───────────────────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task DeleteRemovesEntry(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("a", Encoding.UTF8.GetBytes("A"));
        await store.PutAsync("b", Encoding.UTF8.GetBytes("B"));
        await store.DeleteAsync("a");

        Assert.IsNull(await store.GetAsync("a"), "GetAsync('a') should be null after delete");
        Assert.IsNotNull(await store.GetAsync("b"));
        CollectionAssert.DoesNotContain((System.Collections.ICollection)store.ListIds(), "a");
        CollectionAssert.Contains((System.Collections.ICollection)store.ListIds(), "b");
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task DeleteNonExistentId_IsNoOp(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("a", Encoding.UTF8.GetBytes("A"));
        await store.DeleteAsync("does-not-exist"); // must not throw

        Assert.IsNotNull(await store.GetAsync("a"));
    }

    // ── Compact ──────────────────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task CompactShrinksStore(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("keep", Encoding.UTF8.GetBytes("live"));
        await store.PutAsync("gone", Encoding.UTF8.GetBytes("dead"));
        await store.DeleteAsync("gone");

        long before = await ms.GetLengthAsync();
        await store.CompactAsync();
        long after = await ms.GetLengthAsync();

        Assert.IsTrue(after <= before, $"Expected length to shrink or equal, got {before} → {after}");
        Assert.AreEqual("live", Encoding.UTF8.GetString((await store.GetAsync("keep"))!));
        Assert.IsNull(await store.GetAsync("gone"));
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task PutOverwriteLastWinsAfterCompact(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("k", Encoding.UTF8.GetBytes("v1"));
        await store.PutAsync("k", Encoding.UTF8.GetBytes("v2"));
        Assert.AreEqual("v2", Encoding.UTF8.GetString((await store.GetAsync("k"))!));

        await store.CompactAsync();
        Assert.AreEqual("v2", Encoding.UTF8.GetString((await store.GetAsync("k"))!));
    }

    // ── Persist & reopen ─────────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task ReopenRestoresData(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();

        await using (var store = await CreateStoreAsync(ms, aead))
            await store.PutAsync("x", Encoding.UTF8.GetBytes("persistent"));

        await using var store2 = await CreateStoreAsync(ms, aead);
        var got = await store2.GetAsync("x");
        Assert.IsNotNull(got);
        Assert.AreEqual("persistent", Encoding.UTF8.GetString(got!));
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task ReopenRestoresMultipleEntries(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();

        await using (var store = await CreateStoreAsync(ms, aead))
        {
            for (int i = 0; i < 20; i++)
                await store.PutAsync($"key:{i}", Encoding.UTF8.GetBytes($"value:{i}"));
        }

        await using var store2 = await CreateStoreAsync(ms, aead);
        for (int i = 0; i < 20; i++)
        {
            var got = await store2.GetAsync($"key:{i}");
            Assert.IsNotNull(got, $"key:{i} should be present after reopen");
            Assert.AreEqual($"value:{i}", Encoding.UTF8.GetString(got!));
        }
    }

    // ── Session credentials ───────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task WrongPasswordOnReopenThrows(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();

        await using (var store = await CreateStoreAsync(ms, aead))
            await store.PutAsync("x", Encoding.UTF8.GetBytes("data"));

        await Assert.ThrowsExactlyAsync<CryptographicException>(async () =>
            await CreateStoreAsync(ms, aead,
                password: Encoding.UTF8.GetBytes("wrong-password")));
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task WrongSessionIterationsOnReopenThrows(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();

        // Create with sessionIters=1
        await using (var store = await CreateStoreAsync(ms, aead, sessionIters: 1))
            await store.PutAsync("x", Encoding.UTF8.GetBytes("data"));

        // Reopen with sessionIters=2 — KEK is different, header decryption fails
        await Assert.ThrowsExactlyAsync<CryptographicException>(async () =>
            await CreateStoreAsync(ms, aead, sessionIters: 2));
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task WrongSessionSaltLengthOnReopenThrows(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();

        // Create with saltLen=16
        await using (var store = await CreateStoreAsync(ms, aead, sessionSaltLen: 16))
            await store.PutAsync("x", Encoding.UTF8.GetBytes("data"));

        // Reopen with saltLen=32 — reads wrong bytes as salt, header decryption fails.
        // MSTest ThrowsExactlyAsync matches exact type only, so catch manually.
        bool threw = false;
        try { await CreateStoreAsync(ms, aead, sessionSaltLen: 32); }
        catch (CryptographicException) { threw = true; }
        catch (InvalidDataException) { threw = true; }
        Assert.IsTrue(threw, "Expected an exception when opening with wrong salt length.");
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task CustomSessionSaltLength_RoundtripWorks(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();

        await using (var store = await CreateStoreAsync(ms, aead, sessionSaltLen: 64))
            await store.PutAsync("k", Encoding.UTF8.GetBytes("v"));

        await using var store2 = await CreateStoreAsync(ms, aead, sessionSaltLen: 64);
        var got = await store2.GetAsync("k");
        Assert.IsNotNull(got);
        Assert.AreEqual("v", Encoding.UTF8.GetString(got!));
    }

    // ── Wrong AEAD on reopen ─────────────────────────────────────────────────

    [TestMethod]
    public async Task ReopenWithWrongAeadThrows()
    {
        var ms = new MemoryAppendOnlyStoreProvider();
        await using (var store = await CreateStoreAsync(ms, new AesCtrHmacSha256Provider()))
            await store.PutAsync("x", Encoding.UTF8.GetBytes("data"));

        // In v0x01 the AeadId is inside the encrypted header, so it can only be verified
        // after decryption. With the wrong AEAD provider the header decryption itself fails
        // (CryptographicException) before the AeadId check (InvalidOperationException) is
        // reached. Either exception is a valid signal that the store cannot be opened.
        bool threw = false;
        try
        {
            await CreateStoreAsync(ms, new ChaCha20Poly1305Provider());
        }
        catch (InvalidOperationException) { threw = true; }
        catch (CryptographicException) { threw = true; }
        Assert.IsTrue(threw, "Expected an exception when opening with the wrong AEAD provider.");
    }

    // ── Opacity: file must look like noise ───────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task FileHasNoVisibleMagicOrStructure(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("secret-key", Encoding.UTF8.GetBytes("secret-value"));

        long fileLen = await ms.GetLengthAsync();
        byte[] buf = new byte[fileLen];
        await ms.ReadAtAsync(0, buf);

        // "EES1" magic must NOT appear in plaintext anywhere
        byte[] magic = "EES1"u8.ToArray();
        bool found = false;
        for (int i = 0; i <= buf.Length - magic.Length; i++)
            if (buf.AsSpan(i, magic.Length).SequenceEqual(magic))
            { found = true; break; }

        Assert.IsFalse(found, "Magic bytes 'EES1' must not appear in plaintext in v0x01.");

        // Key must NOT appear in plaintext
        byte[] keyBytes = Encoding.UTF8.GetBytes("secret-key");
        bool keyFound = false;
        for (int i = 0; i <= buf.Length - keyBytes.Length; i++)
            if (buf.AsSpan(i, keyBytes.Length).SequenceEqual(keyBytes))
            { keyFound = true; break; }

        Assert.IsFalse(keyFound, "Key 'secret-key' must not appear in plaintext in v0x01.");
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task TwoStoresWithSamePassword_FilesDiffer(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms1 = new MemoryAppendOnlyStoreProvider();
        var ms2 = new MemoryAppendOnlyStoreProvider();

        await using (var s1 = await CreateStoreAsync(ms1, aead))
        await using (var s2 = await CreateStoreAsync(ms2, aead))
        {
            await s1.PutAsync("k", Encoding.UTF8.GetBytes("v"));
            await s2.PutAsync("k", Encoding.UTF8.GetBytes("v"));
        }

        long len1 = await ms1.GetLengthAsync();
        long len2 = await ms2.GetLengthAsync();
        byte[] buf1 = new byte[len1];
        byte[] buf2 = new byte[len2];
        await ms1.ReadAtAsync(0, buf1);
        await ms2.ReadAtAsync(0, buf2);

        // Files with same content and same password must produce different ciphertext
        // (different salts, different DEKs, different nonces)
        Assert.IsFalse(buf1.AsSpan(0, (int)Math.Min(len1, len2))
                           .SequenceEqual(buf2.AsSpan(0, (int)Math.Min(len1, len2))),
            "Two stores with same password must produce different ciphertext.");
    }

    /// <summary>Checks the actual AEAD inputs across writes, reopen and compaction.</summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task RecordKeyNoncePairs_AreUniqueAcrossReopenAndCompaction(IAEADProvider aead)
    {
        RecordingAead recorder = new(aead);
        MemoryAppendOnlyStoreProvider backend = new();

        await using (EncryptedEntryStore store = await CreateStoreAsync(backend, recorder))
        {
            recorder.Encryptions.Clear();
            await store.PutAsync("keep", "first"u8.ToArray());
            await store.PutAsync("gone", "second"u8.ToArray());
            await store.DeleteAsync("gone");
        }

        await using (EncryptedEntryStore store = await CreateStoreAsync(backend, recorder))
        {
            await store.PutAsync("new", "third"u8.ToArray());
            await store.CompactAsync();
            Assert.IsNull(await store.GetAsync("gone"));
        }

        Assert.AreEqual(12, recorder.Encryptions.Count);
        Assert.AreEqual(12, recorder.Encryptions.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>Checks file offsets after random reads and concurrent store operations.</summary>
    [TestMethod]
    public async Task FileStore_ReadThenConcurrentPuts_SurviveReopen()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".hoddmir");
        try
        {
            await using (FileAppendOnlyStoreProvider backend = new(path))
            await using (EncryptedEntryStore store = await CreateStoreAsync(backend, new AesGcmProvider()))
            {
                await store.PutAsync("first", "first value"u8.ToArray());
                await store.PutAsync("second", "second value"u8.ToArray());
                CollectionAssert.AreEqual("first value"u8.ToArray(), await store.GetAsync("first"));
                await Task.WhenAll(Enumerable.Range(0, 12)
                                             .Select(i => store.PutAsync($"key-{i}", BitConverter.GetBytes(i))));
            }

            await using FileAppendOnlyStoreProvider reopenedBackend = new(path);
            await using EncryptedEntryStore reopened = await CreateStoreAsync(reopenedBackend, new AesGcmBouncyCastleProvider());
            CollectionAssert.AreEqual("first value"u8.ToArray(), await reopened.GetAsync("first"));
            CollectionAssert.AreEqual("second value"u8.ToArray(), await reopened.GetAsync("second"));
            for (int i = 0; i < 12; i++)
                CollectionAssert.AreEqual(BitConverter.GetBytes(i), await reopened.GetAsync($"key-{i}"));

            Assert.IsTrue((await reopened.VerifyAsync()).IsHealthy);
        }
        finally
        {
            File.Delete(path);
            File.Delete(path + ".lock");
        }
    }

    /// <summary>Recovers committed records and compacts away an incomplete append.</summary>
    [TestMethod]
    public async Task FileStore_IncompleteTail_CanBeRecoveredByCompaction()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".hoddmir");
        byte[] checkpoint;
        try
        {
            await using (FileAppendOnlyStoreProvider backend = new(path))
            await using (EncryptedEntryStore store = await CreateStoreAsync(backend, new AesGcmProvider()))
            {
                await store.PutAsync("committed", "value"u8.ToArray());
                checkpoint = await store.GetCheckpointAsync();
                await store.PutAsync("incomplete", "value"u8.ToArray());
            }

            using (FileStream file = new(path, FileMode.Open, FileAccess.Write))
                file.SetLength(file.Length - 5);

            await using FileAppendOnlyStoreProvider reopenedBackend = new(path);
            await using EncryptedEntryStore reopened = await EncryptedEntryStore.Configure()
                .WithPassword(Password)
                .WithSessionIterations(1)
                .WithAead(new AesGcmProvider())
                .OpenAtCheckpointAsync(reopenedBackend, reopenedBackend, checkpoint);
            CollectionAssert.AreEqual("value"u8.ToArray(), await reopened.GetAsync("committed"));
            Assert.IsNull(await reopened.GetAsync("incomplete"));
            Assert.AreEqual(1, (await reopened.VerifyAsync()).TruncatedRecords);
            await Assert.ThrowsExactlyAsync<InvalidDataException>(() => reopened.PutAsync("next", "value"u8.ToArray()));
            await reopened.CompactAsync();
            await reopened.PutAsync("next", "value"u8.ToArray());
            Assert.IsTrue((await reopened.VerifyAsync()).IsHealthy);
        }
        finally
        {
            File.Delete(path);
            File.Delete(path + ".lock");
        }
    }

    /// <summary>Rejects a same-offset record from an older snapshot after compaction.</summary>
    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task ReplayedRecord_CannotBeCombinedWithNewHistory(IAEADProvider aead)
    {
        const int headerSize = 16 + 512;
        MemoryAppendOnlyStoreProvider backend = new();
        byte[] oldSnapshot;
        byte[] currentSnapshot;
        byte[] checkpoint;

        await using (EncryptedEntryStore store = await CreateStoreAsync(backend, aead))
        {
            await store.PutAsync("role", "allow"u8.ToArray());
            oldSnapshot = new byte[(int)await backend.GetLengthAsync()];
            Assert.AreEqual(oldSnapshot.Length, await backend.ReadAtAsync(0, oldSnapshot));

            await store.PutAsync("role", "block"u8.ToArray());
            // Both values have the same length. Retry until random padding matches.
            for (int attempt = 0; attempt < 2048; attempt++)
            {
                await store.CompactAsync();
                if (await backend.GetLengthAsync() == oldSnapshot.Length)
                    break;
            }
            Assert.AreEqual((long)oldSnapshot.Length, await backend.GetLengthAsync());

            await store.PutAsync("current", "new"u8.ToArray());
            currentSnapshot = new byte[(int)await backend.GetLengthAsync()];
            Assert.AreEqual(currentSnapshot.Length, await backend.ReadAtAsync(0, currentSnapshot));
            checkpoint = await store.GetCheckpointAsync();
        }

        EncryptedEntryStore.StoreBuilder builder = EncryptedEntryStore.Configure()
            .WithPassword(Password)
            .WithAead(aead)
            .WithSessionIterations(1);
        await using (EncryptedEntryStore reopened = await builder.OpenAtCheckpointAsync(backend, backend, checkpoint))
            CollectionAssert.AreEqual("block"u8.ToArray(), await reopened.GetAsync("role"));

        oldSnapshot.AsSpan(headerSize).CopyTo(currentSnapshot.AsSpan(headerSize));
        await backend.ReplaceWithAsync(stream => stream.WriteAsync(currentSnapshot).AsTask());
        await Assert.ThrowsExactlyAsync<InvalidDataException>(() => CreateStoreAsync(backend, aead));

        await backend.ReplaceWithAsync(stream => stream.WriteAsync(oldSnapshot).AsTask());
        await Assert.ThrowsExactlyAsync<InvalidDataException>(() => builder.OpenAtCheckpointAsync(backend, backend, checkpoint));
    }

    /// <summary>Refuses a second attachment and releases the backend when the first store closes.</summary>
    [TestMethod]
    public async Task SecondAttachment_CannotWriteToSharedBackend()
    {
        MemoryAppendOnlyStoreProvider backend = new();
        AesGcmProvider aead = new();
        await using (EncryptedEntryStore store = await CreateStoreAsync(backend, aead))
        {
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => CreateStoreAsync(backend, aead));
            await store.PutAsync("key", "value"u8.ToArray());
        }
        await using EncryptedEntryStore reopened = await CreateStoreAsync(backend, aead);
        CollectionAssert.AreEqual("value"u8.ToArray(), await reopened.GetAsync("key"));
    }

    /// <summary>Rejects missing content when opening and rejects existing content when creating.</summary>
    [TestMethod]
    public async Task StrictOpenAndCreate_DistinguishEmptyAndExistingBackends()
    {
        MemoryAppendOnlyStoreProvider backend = new();
        EncryptedEntryStore.StoreBuilder builder = EncryptedEntryStore.Configure()
            .WithPassword(Password)
            .WithAead(new AesGcmProvider())
            .WithSessionIterations(1)
            .WithDekArgon2id(FastDekArgon);

        await Assert.ThrowsExactlyAsync<InvalidDataException>(() => builder.OpenExistingAsync(backend, backend));
        await using (EncryptedEntryStore store = await builder.CreateAsync(backend, backend))
            await store.PutAsync("key", "value"u8.ToArray());
        await Assert.ThrowsExactlyAsync<IOException>(() => builder.CreateAsync(backend, backend));
        await using EncryptedEntryStore reopened = await builder.OpenExistingAsync(backend, backend);
        CollectionAssert.AreEqual("value"u8.ToArray(), await reopened.GetAsync("key"));
    }

    // ── DEK rotation ────────────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task RotateDek_DataSurvivesRotation(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("a", Encoding.UTF8.GetBytes("alpha"));
        await store.PutAsync("b", Encoding.UTF8.GetBytes("beta"));
        await store.DeleteAsync("a");

        await store.RotateDekAsync(Password);

        Assert.IsNull(await store.GetAsync("a"), "Deleted entry must remain absent after rotation.");
        var b = await store.GetAsync("b");
        Assert.IsNotNull(b);
        Assert.AreEqual("beta", Encoding.UTF8.GetString(b!));
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task RotateDek_ReopenAfterRotationWorks(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("x", Encoding.UTF8.GetBytes("original"));

        byte[] newPassword = Encoding.UTF8.GetBytes("new-password");
        await store.RotateDekAsync(Password, newPasswordUtf8: newPassword);
        await store.DisposeAsync();

        // Reopen with new password — must succeed
        await store.DisposeAsync();
        await using var store2 = await CreateStoreAsync(ms, aead, password: newPassword);
        var got = await store2.GetAsync("x");
        Assert.IsNotNull(got);
        Assert.AreEqual("original", Encoding.UTF8.GetString(got!));
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task RotateDek_OldPasswordFailsAfterRotation(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);
        await store.PutAsync("k", Encoding.UTF8.GetBytes("v"));

        byte[] newPassword = Encoding.UTF8.GetBytes("new-password");
        await store.RotateDekAsync(Password, newPasswordUtf8: newPassword);
        await store.DisposeAsync();

        await store.DisposeAsync();
        await Assert.ThrowsExactlyAsync<CryptographicException>(async () =>
            await CreateStoreAsync(ms, aead, password: Password));
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task RotateDek_WrongCurrentPasswordThrows(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);
        await store.PutAsync("k", Encoding.UTF8.GetBytes("v"));

        byte[] wrong = Encoding.UTF8.GetBytes("wrong-password");
        await Assert.ThrowsExactlyAsync<CryptographicException>(async () =>
            await store.RotateDekAsync(wrong));

        // Store must still be readable with original password after failed rotation
        var got = await store.GetAsync("k");
        Assert.IsNotNull(got);
        Assert.AreEqual("v", Encoding.UTF8.GetString(got!));
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task RotateDek_FileDiffersAfterRotation(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);
        await store.PutAsync("k", Encoding.UTF8.GetBytes("v"));

        long lenBefore = await ms.GetLengthAsync();
        byte[] before = new byte[lenBefore];
        await ms.ReadAtAsync(0, before);

        await store.RotateDekAsync(Password);

        long lenAfter = await ms.GetLengthAsync();
        byte[] after = new byte[lenAfter];
        await ms.ReadAtAsync(0, after);

        // File bytes must differ after rotation (new DEK, new nonces, new salt)
        Assert.IsFalse(before.AsSpan(0, (int)Math.Min(lenBefore, lenAfter))
                             .SequenceEqual(after.AsSpan(0, (int)Math.Min(lenBefore, lenAfter))),
            "File must differ after DEK rotation.");
    }

    // ── ListIds ───────────────────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task ListIds_ReturnsOnlyLiveIds(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("a", Encoding.UTF8.GetBytes("A"));
        await store.PutAsync("b", Encoding.UTF8.GetBytes("B"));
        await store.PutAsync("c", Encoding.UTF8.GetBytes("C"));
        await store.DeleteAsync("b");

        var ids = store.ListIds();
        CollectionAssert.Contains((System.Collections.ICollection)ids, "a");
        CollectionAssert.DoesNotContain((System.Collections.ICollection)ids, "b");
        CollectionAssert.Contains((System.Collections.ICollection)ids, "c");
        Assert.AreEqual(2, ids.Count);
    }

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task ListIds_RestoredCorrectlyAfterReopen(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();

        await using (var store = await CreateStoreAsync(ms, aead))
        {
            await store.PutAsync("x", Encoding.UTF8.GetBytes("X"));
            await store.PutAsync("y", Encoding.UTF8.GetBytes("Y"));
            await store.DeleteAsync("x");
        }

        await using var store2 = await CreateStoreAsync(ms, aead);
        var ids = store2.ListIds();

        CollectionAssert.DoesNotContain((System.Collections.ICollection)ids, "x");
        CollectionAssert.Contains((System.Collections.ICollection)ids, "y");
        Assert.AreEqual(1, ids.Count);
    }

    // ── VerifyAsync ───────────────────────────────────────────────────────────

    [TestMethod]
    [DynamicData(nameof(Providers), DynamicDataSourceType.Method)]
    public async Task VerifyAsync_HealthyStore(IAEADProvider aead)
    {
        Trace.WriteLine($"Provider: {aead}");
        var ms = new MemoryAppendOnlyStoreProvider();
        await using var store = await CreateStoreAsync(ms, aead);

        await store.PutAsync("a", Encoding.UTF8.GetBytes("alpha"));
        await store.PutAsync("b", Encoding.UTF8.GetBytes("beta"));

        var result = await store.VerifyAsync();
        Assert.IsTrue(result.IsHealthy);
        Assert.AreEqual(0, result.CorruptedRecords);
        Assert.AreEqual(0, result.TruncatedRecords);
    }

    // ── Providers ─────────────────────────────────────────────────────────────

    private static IEnumerable<object[]> Providers() =>
    [
        [new AesGcmProvider()],
        [new AesCtrHmacSha256Provider()],
        [new ChaCha20Poly1305Provider()],
    ];

    private sealed class RecordingAead : IAEADProvider
    {
        #region Fields

        private readonly IAEADProvider inner;

        #endregion

        #region Properties

        public List<string> Encryptions { get; } = [];
        public string Name => this.inner.Name;
        public int KeySizeBytes => this.inner.KeySizeBytes;
        public int NonceSizeBytes => this.inner.NonceSizeBytes;
        public int TagSizeBytes => this.inner.TagSizeBytes;

        #endregion

        #region .ctor

        /// <summary>Wraps the provider used by the store without changing its algorithm ID.</summary>
        public RecordingAead(IAEADProvider inner) => this.inner = inner;

        #endregion

        #region Methods

        /// <inheritdoc />
        public void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                            ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag)
        {
            this.Encryptions.Add(Convert.ToHexString(SHA256.HashData(key)) + Convert.ToHexString(nonce));
            this.inner.Encrypt(key, nonce, aad, plaintext, ciphertext, tag);
        }

        /// <inheritdoc />
        public bool Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
                            ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext) =>
            this.inner.Decrypt(key, nonce, aad, ciphertext, tag, plaintext);

        #endregion
    }
}
