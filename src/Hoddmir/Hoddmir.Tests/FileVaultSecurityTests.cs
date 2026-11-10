using Hoddmir.Core.Encryption.AEAD;
using Hoddmir.Core.Keys;
using Hoddmir.Storage;
using Hoddmir.Storage.Providers;
using System.Security.Cryptography;

namespace Hoddmir.Tests;

/// <summary>Exercises adversarial changes and recovery against real vault files.</summary>
[TestClass]
[TestCategory("VaultSecurity")]
[DoNotParallelize]
public sealed class FileVaultSecurityTests
{
    #region Fields

    private readonly string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".hoddmir");

    #endregion

    #region Methods

    /// <summary>Removes the temporary vault and its writer lock.</summary>
    [TestCleanup]
    public void DeleteVault()
    {
        File.Delete(this.path);
        File.Delete(this.path + ".lock");
    }

    /// <summary>Rejects bit flips in the header, the record salt and the payload tags.</summary>
    [TestMethod]
    [DataRow("header-tag")]
    [DataRow("first-record-salt")]
    [DataRow("superseded-value-tag")]
    [DataRow("latest-value-tag")]
    public async Task BitFlip_IsRejectedOnOpen(string target)
    {
        EncryptedEntryStore.StoreBuilder builder = ConfigureVault();
        (int headerEnd, int firstEnd, _, _) = await this.CreateHistoryAsync(builder);
        byte[] attacked = await File.ReadAllBytesAsync(this.path);
        int offset = target switch
        {
            "header-tag" => headerEnd - 1,
            "first-record-salt" => headerEnd,
            "superseded-value-tag" => firstEnd - 1,
            "latest-value-tag" => attacked.Length - 1,
            _ => throw new ArgumentOutOfRangeException(nameof(target))
        };
        attacked[offset] ^= 1;
        await File.WriteAllBytesAsync(this.path, attacked);

        await using FileAppendOnlyStoreProvider backend = new(this.path);
        if (target == "header-tag")
            await Assert.ThrowsExactlyAsync<CryptographicException>(() => builder.OpenAsync(backend, backend));
        else
            await Assert.ThrowsExactlyAsync<InvalidDataException>(() => builder.OpenAsync(backend, backend));
    }

    /// <summary>Rejects valid ciphertext moved to a different position in the log.</summary>
    [TestMethod]
    [DataRow("remove-first")]
    [DataRow("swap")]
    [DataRow("append-duplicate")]
    public async Task RearrangedRecords_AreRejectedOnOpen(string manipulation)
    {
        EncryptedEntryStore.StoreBuilder builder = ConfigureVault();
        (int headerEnd, int firstEnd, _, _) = await this.CreateHistoryAsync(builder);
        byte[] original = await File.ReadAllBytesAsync(this.path);
        byte[] attacked = manipulation switch
        {
            "remove-first" => [.. original.AsSpan(0, headerEnd), .. original.AsSpan(firstEnd)],
            "swap" => [.. original.AsSpan(0, headerEnd), .. original.AsSpan(firstEnd), .. original.AsSpan(headerEnd, firstEnd - headerEnd)],
            "append-duplicate" => [.. original, .. original.AsSpan(firstEnd)],
            _ => throw new ArgumentOutOfRangeException(nameof(manipulation))
        };
        await File.WriteAllBytesAsync(this.path, attacked);

        await using FileAppendOnlyStoreProvider backend = new(this.path);
        await Assert.ThrowsExactlyAsync<InvalidDataException>(() => builder.OpenAsync(backend, backend));
    }

    /// <summary>Rejects an otherwise valid older snapshot with the latest trusted checkpoint.</summary>
    [TestMethod]
    public async Task CompleteRollback_IsRejectedByLatestCheckpoint()
    {
        EncryptedEntryStore.StoreBuilder builder = ConfigureVault();
        (_, int firstEnd, byte[] firstCheckpoint, byte[] latestCheckpoint) = await this.CreateHistoryAsync(builder);
        byte[] original = await File.ReadAllBytesAsync(this.path);
        await File.WriteAllBytesAsync(this.path, original[..firstEnd]);

        await using FileAppendOnlyStoreProvider backend = new(this.path);
        await Assert.ThrowsExactlyAsync<InvalidDataException>(() => builder.OpenAtCheckpointAsync(backend, backend, latestCheckpoint));
        await using EncryptedEntryStore older = await builder.OpenAtCheckpointAsync(backend, backend, firstCheckpoint);
        CollectionAssert.AreEqual("allow"u8.ToArray(), await older.GetAsync("role"));
        Assert.IsTrue((await older.VerifyAsync()).IsHealthy);
    }

    /// <summary>Recovers only the complete history that matches the trusted checkpoint.</summary>
    [TestMethod]
    public async Task IncompleteTail_RecoversMatchingPrefixAndPersistsNewWrites()
    {
        EncryptedEntryStore.StoreBuilder builder = ConfigureVault();
        (_, int firstEnd, byte[] firstCheckpoint, byte[] latestCheckpoint) = await this.CreateHistoryAsync(builder);
        byte[] original = await File.ReadAllBytesAsync(this.path);
        await File.WriteAllBytesAsync(this.path, original[..^1]);
        byte[] recoveredCheckpoint;

        await using (FileAppendOnlyStoreProvider backend = new(this.path))
        {
            await Assert.ThrowsExactlyAsync<InvalidDataException>(() => builder.OpenAtCheckpointAsync(backend, backend, latestCheckpoint));
            await using EncryptedEntryStore recovered = await builder.OpenAtCheckpointAsync(backend, backend, firstCheckpoint);
            VerifyResult verification = await recovered.VerifyAsync();
            CollectionAssert.AreEqual(new long[] { firstEnd }, verification.TruncatedOffsets.ToArray());
            Assert.AreEqual(0, verification.CorruptedRecords);
            CollectionAssert.AreEqual("allow"u8.ToArray(), await recovered.GetAsync("role"));
            await Assert.ThrowsExactlyAsync<InvalidDataException>(() => recovered.PutAsync("next", "value"u8.ToArray()));
            Assert.AreEqual(original.LongLength - 1, await backend.GetLengthAsync());

            await recovered.CompactAsync();
            Assert.IsTrue((await recovered.VerifyAsync()).IsHealthy);
            await recovered.PutAsync("next", "value"u8.ToArray());
            recoveredCheckpoint = await recovered.GetCheckpointAsync();
        }

        await using FileAppendOnlyStoreProvider reopenedBackend = new(this.path);
        await using EncryptedEntryStore reopened = await builder.OpenAtCheckpointAsync(reopenedBackend, reopenedBackend, recoveredCheckpoint);
        CollectionAssert.AreEqual("allow"u8.ToArray(), await reopened.GetAsync("role"));
        CollectionAssert.AreEqual("value"u8.ToArray(), await reopened.GetAsync("next"));
        Assert.IsTrue((await reopened.VerifyAsync()).IsHealthy);
    }

    /// <summary>Rejects a valid file that exceeds the reader's configured resource limits.</summary>
    [TestMethod]
    [DataRow(1, 5, 6)]
    [DataRow(2, 4, 6)]
    [DataRow(2, 5, 5)]
    public async Task AuthenticatedFile_EnforcesReaderLimits(int maxIds, int maxIdBytes, int maxRecordBytes)
    {
        EncryptedEntryStore.StoreBuilder builder = ConfigureVault().WithResourceLimits(2, 5, 6);
        await using (FileAppendOnlyStoreProvider backend = new(this.path, FileMode.CreateNew))
        await using (EncryptedEntryStore store = await builder.CreateAsync(backend, backend))
        {
            await store.PutAsync("é", "a"u8.ToArray());
            await store.PutAsync("bbb", "bbb"u8.ToArray());
        }

        await using FileAppendOnlyStoreProvider reopenedBackend = new(this.path);
        await using (EncryptedEntryStore original = await builder.OpenAsync(reopenedBackend, reopenedBackend))
        {
            CollectionAssert.AreEqual("bbb"u8.ToArray(), await original.GetAsync("bbb"));
            Assert.AreEqual(2, original.ListIds().Count);
        }

        builder.WithResourceLimits(maxIds, maxIdBytes, maxRecordBytes);
        await Assert.ThrowsExactlyAsync<InvalidDataException>(() => builder.OpenAsync(reopenedBackend, reopenedBackend));
    }

    /// <summary>Recovers the trusted prefix when an append fails after writing part of a record.</summary>
    [TestMethod]
    public async Task PartialAppend_RecoversAtPreviousCheckpoint()
    {
        EncryptedEntryStore.StoreBuilder builder = ConfigureVault();
        (_, _, _, byte[] checkpoint) = await this.CreateHistoryAsync(builder);
        long committedLength = new FileInfo(this.path).Length;
        byte[] value = new byte[512];
        value[^1] = 42;

        await this.SimulateFailedWriteAsync(builder, checkpoint, value, truncateAppend: true);

        await using FileAppendOnlyStoreProvider backend = new(this.path);
        await using EncryptedEntryStore recovered = await builder.OpenAtCheckpointAsync(backend, backend, checkpoint);
        VerifyResult verification = await recovered.VerifyAsync();
        CollectionAssert.AreEqual(new long[] { committedLength }, verification.TruncatedOffsets.ToArray());
        Assert.AreEqual(0, verification.CorruptedRecords);
        CollectionAssert.AreEqual("block"u8.ToArray(), await recovered.GetAsync("role"));
        Assert.IsNull(await recovered.GetAsync("candidate"));
        await Assert.ThrowsExactlyAsync<InvalidDataException>(() => recovered.PutAsync("candidate", value));

        await recovered.CompactAsync();
        await recovered.PutAsync("candidate", value);
        CollectionAssert.AreEqual(value, await recovered.GetAsync("candidate"));
        Assert.IsTrue((await recovered.VerifyAsync()).IsHealthy);
    }

    /// <summary>Requires a fresh open when a complete append survives a reported flush error.</summary>
    [TestMethod]
    public async Task FlushFailure_SurvivingRecordRequiresCheckpointReconciliation()
    {
        EncryptedEntryStore.StoreBuilder builder = ConfigureVault();
        (_, _, _, byte[] checkpoint) = await this.CreateHistoryAsync(builder);
        byte[] value = "candidate-value"u8.ToArray();

        await this.SimulateFailedWriteAsync(builder, checkpoint, value, truncateAppend: false);

        await using FileAppendOnlyStoreProvider backend = new(this.path);
        await Assert.ThrowsExactlyAsync<InvalidDataException>(() => builder.OpenAtCheckpointAsync(backend, backend, checkpoint));

        // Authenticate the surviving file separately from deciding whether to trust its new head.
        await using EncryptedEntryStore inspected = await builder.OpenAsync(backend, backend);
        CollectionAssert.AreEqual("block"u8.ToArray(), await inspected.GetAsync("role"));
        CollectionAssert.AreEqual(value, await inspected.GetAsync("candidate"));
        Assert.IsTrue((await inspected.VerifyAsync()).IsHealthy);
    }

    /// <summary>Preserves the previous committed file if a rewrite fails before publishing it.</summary>
    [TestMethod]
    public async Task FailedCompaction_PreservesCommittedFileForReopen()
    {
        EncryptedEntryStore.StoreBuilder builder = ConfigureVault();
        (_, _, _, byte[] latestCheckpoint) = await this.CreateHistoryAsync(builder);
        byte[] original = await File.ReadAllBytesAsync(this.path);

        await using (FileAppendOnlyStoreProvider backend = new(this.path))
        await using (EncryptedEntryStore store = await builder.OpenAsync(backend, new FailingReplace(backend)))
        {
            IOException error = await Assert.ThrowsExactlyAsync<IOException>(() => store.CompactAsync());
            Assert.AreEqual("Simulated failure before publishing the replacement.", error.Message);
        }

        CollectionAssert.AreEqual(original, await File.ReadAllBytesAsync(this.path));
        await using FileAppendOnlyStoreProvider reopenedBackend = new(this.path);
        await using EncryptedEntryStore reopened = await builder.OpenAtCheckpointAsync(reopenedBackend, reopenedBackend, latestCheckpoint);
        await reopened.CompactAsync();
        CollectionAssert.AreEqual("block"u8.ToArray(), await reopened.GetAsync("role"));
        Assert.IsTrue((await reopened.VerifyAsync()).IsHealthy);
    }

    /// <summary>Excludes a second file writer before and after replacing the vault.</summary>
    [TestMethod]
    public async Task SecondWriter_IsExcludedAcrossCompaction()
    {
        EncryptedEntryStore.StoreBuilder builder = ConfigureVault();
        await this.CreateHistoryAsync(builder);

        await using (FileAppendOnlyStoreProvider backend = new(this.path))
        await using (EncryptedEntryStore store = await builder.OpenAsync(backend, backend))
        {
            await Assert.ThrowsExactlyAsync<IOException>(this.OpenAndCloseFileAsync);
            await store.CompactAsync();
            await Assert.ThrowsExactlyAsync<IOException>(this.OpenAndCloseFileAsync);
        }

        await this.OpenAndCloseFileAsync();
    }

    /// <summary>Configures AES-GCM and real Argon2id with reduced test costs.</summary>
    private static EncryptedEntryStore.StoreBuilder ConfigureVault() =>
        EncryptedEntryStore.Configure()
            .WithPassword("temporary-vault-password"u8.ToArray())
            .WithSessionIterations(1)
            .WithDekArgon2id(new FixedArgon2idParamsProvider(new Argon2idParams(32 * 1024, 1, 1)))
            .WithAead(new AesGcmProvider());

    /// <summary>Builds a valid file and records its boundaries before any manipulation.</summary>
    private async Task<(int HeaderEnd, int FirstEnd, byte[] FirstCheckpoint, byte[] LatestCheckpoint)> CreateHistoryAsync(EncryptedEntryStore.StoreBuilder builder)
    {
        int headerEnd;
        int firstEnd;
        byte[] firstCheckpoint;
        byte[] latestCheckpoint;

        await using (FileAppendOnlyStoreProvider backend = new(this.path, FileMode.CreateNew))
        await using (EncryptedEntryStore store = await builder.CreateAsync(backend, backend))
        {
            headerEnd = checked((int)await backend.GetLengthAsync());
            await store.PutAsync("role", "allow"u8.ToArray());
            firstEnd = checked((int)await backend.GetLengthAsync());
            firstCheckpoint = await store.GetCheckpointAsync();
            await store.PutAsync("role", "block"u8.ToArray());
            latestCheckpoint = await store.GetCheckpointAsync();
        }

        await using FileAppendOnlyStoreProvider reopenedBackend = new(this.path);
        await using EncryptedEntryStore reopened = await builder.OpenAtCheckpointAsync(reopenedBackend, reopenedBackend, latestCheckpoint);
        CollectionAssert.AreEqual("block"u8.ToArray(), await reopened.GetAsync("role"));
        Assert.IsTrue((await reopened.VerifyAsync()).IsHealthy);
        return (headerEnd, firstEnd, firstCheckpoint, latestCheckpoint);
    }

    /// <summary>Attempts to acquire an independent file backend and releases it if successful.</summary>
    private async Task OpenAndCloseFileAsync()
    {
        await using FileAppendOnlyStoreProvider backend = new(this.path);
    }

    /// <summary>Injects one write fault and verifies that the same store cannot continue writing.</summary>
    private async Task SimulateFailedWriteAsync(EncryptedEntryStore.StoreBuilder builder,
                                                byte[] checkpoint,
                                                byte[] value,
                                                bool truncateAppend)
    {
        await using FileAppendOnlyStoreProvider backend = new(this.path);
        FailingWriteBackend fault = new(backend, truncateAppend);
        await using EncryptedEntryStore store = await builder.OpenAtCheckpointAsync(fault, backend, checkpoint);
        long originalLength = await backend.GetLengthAsync();

        IOException error = await Assert.ThrowsExactlyAsync<IOException>(() => store.PutAsync("candidate", value));
        Assert.AreSame(fault.Failure, error);
        long faultedLength = await backend.GetLengthAsync();
        Assert.IsTrue(faultedLength > originalLength);
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.GetCheckpointAsync());
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.PutAsync("retry", value));
        Assert.AreEqual(faultedLength, await backend.GetLengthAsync());
    }

    #endregion

    private sealed class FailingWriteBackend : IAppendOnlyStoreProvider
    {
        #region Fields

        private readonly IAppendOnlyStoreProvider inner;
        private readonly bool truncateAppend;
        private bool failNextFlush;

        #endregion

        #region Properties

        public IOException Failure { get; } = new("Simulated vault write failure.");

        #endregion

        #region .ctor

        /// <summary>Wraps a file backend and selects either a partial append or a failed flush.</summary>
        public FailingWriteBackend(IAppendOnlyStoreProvider inner, bool truncateAppend)
        {
            this.inner = inner;
            this.truncateAppend = truncateAppend;
        }

        #endregion

        #region Methods

        /// <inheritdoc />
        public Task<long> GetLengthAsync(CancellationToken ct = default) => this.inner.GetLengthAsync(ct);

        /// <inheritdoc />
        public Task<int> ReadAtAsync(long offset, Memory<byte> buffer, CancellationToken ct = default) =>
            this.inner.ReadAtAsync(offset, buffer, ct);

        /// <inheritdoc />
        public async Task AppendAsync(ReadOnlyMemory<byte> data, long expectedOffset, CancellationToken ct = default)
        {
            ReadOnlyMemory<byte> bytes = this.truncateAppend ? data[..(data.Length / 2)] : data;
            await this.inner.AppendAsync(bytes, expectedOffset, ct);
            if (this.truncateAppend)
                throw this.Failure;

            this.failNextFlush = true;
        }

        /// <inheritdoc />
        public Task FlushAsync(bool hard = false, CancellationToken ct = default)
        {
            if (this.failNextFlush)
            {
                this.failNextFlush = false;
                return Task.FromException(this.Failure);
            }

            return this.inner.FlushAsync(hard, ct);
        }

        #endregion
    }

    private sealed class FailingReplace : IAtomicReplace
    {
        #region Fields

        private readonly IAtomicReplace inner;

        #endregion

        #region .ctor

        /// <summary>Wraps the real file replacement backend.</summary>
        public FailingReplace(IAtomicReplace inner)
        {
            this.inner = inner;
        }

        #endregion

        #region Methods

        /// <summary>Stages the new file and fails before the backend can publish it.</summary>
        public Task ReplaceWithAsync(Func<Stream, Task> buildNew, CancellationToken ct = default) =>
            this.inner.ReplaceWithAsync(async stream =>
            {
                await buildNew(stream);
                throw new IOException("Simulated failure before publishing the replacement.");
            },
                                        ct);

        #endregion
    }
}
