using Hoddmir.Core.Encryption;
using Hoddmir.Core.Keys;
using Hoddmir.Storage;
using Hoddmir.Storage.Providers;
using System.Runtime.CompilerServices;
using System.Text;

namespace Hoddmir.Tests
{
    [TestClass]
    public sealed class InMemoryTests
    {
        #region Fields

        private static readonly byte[] password = Encoding.UTF8.GetBytes("test-password");
        private static readonly IArgon2idParamsProvider fastArgon =
            new FixedArgon2idParamsProvider(new (memoryKib: 32 * 1024,   // 32 MiB: quick for tests
                                                 iterations: 2,
                                                 parallelism: 2));

        #endregion

        #region Methods

        private static async Task<EncryptedEntryStore> CreateStoreAsync(MemoryAppendOnlyStoreProvider memoryStore)
        {
            IAEADProvider aeadProvider = new AesCtrHmacSha256Provider();
            return await CreateStoreAsync(memoryStore, aeadProvider);
        }

        private static async Task<EncryptedEntryStore> CreateStoreAsync(MemoryAppendOnlyStoreProvider memoryStore,
                                                                        IAEADProvider aeadProvider)
        {
            ArgonKeyProvider argonKeyProvider = new();

            return await EncryptedEntryStore.OpenAsync(storeProvider: memoryStore,
                                                       replacer: memoryStore,
                                                       aeadProvider: aeadProvider,
                                                       mode: KeyProtectionMode.PasswordArgon2id,
                                                       passwordUtf8: password,
                                                       argonParamsProvider: fastArgon,
                                                       argonKeyProvider: argonKeyProvider,
                                                       cancellationToken: CancellationToken.None);
        }


        [TestMethod]
        public async Task PutGetRoundtrip()
        {
            MemoryAppendOnlyStoreProvider memoryStore = new ();
            EncryptedEntryStore store = await CreateStoreAsync(memoryStore);

            string id = "user:42";
            byte[] data = Encoding.UTF8.GetBytes("hello, world!");

            await store.PutAsync(id, data);

            byte[]? got = await store.GetAsync(id);
            Assert.IsNotNull(got, "GetAsync returned null");
            CollectionAssert.AreEqual(data, got!, "Decrypted payload doesn't match");

            await store.DisposeAsync();
        }

        [TestMethod]
        public async Task DeleteRemovesFromListAndGetReturnsNull()
        {
            MemoryAppendOnlyStoreProvider memoryStore = new ();
            EncryptedEntryStore store = await CreateStoreAsync(memoryStore);

            await store.PutAsync("a", Encoding.UTF8.GetBytes("A"));
            await store.PutAsync("b", Encoding.UTF8.GetBytes("B"));

            IReadOnlyCollection<string> idsBefore = store.ListIds();
            CollectionAssert.Contains((System.Collections.ICollection)idsBefore, "a");
            CollectionAssert.Contains((System.Collections.ICollection)idsBefore, "b");

            await store.DeleteAsync("a");

            IReadOnlyCollection<string> idsAfter = store.ListIds();
            CollectionAssert.DoesNotContain((System.Collections.ICollection)idsAfter, "a");
            CollectionAssert.Contains((System.Collections.ICollection)idsAfter, "b");

            byte[]? a = await store.GetAsync("a");
            Assert.IsNull(a, "GetAsync('a') should be null after delete");

            byte[]? b = await store.GetAsync("b");
            Assert.IsNotNull(b);
            Assert.AreEqual("B", Encoding.UTF8.GetString(b!));

            await store.DisposeAsync();
        }

        [TestMethod]
        public async Task CompactShrinksUnderlyingLengthWhenThereAreTombstones()
        {
            MemoryAppendOnlyStoreProvider memoryStore = new ();
            EncryptedEntryStore store = await CreateStoreAsync(memoryStore);

            await store.PutAsync("keep", Encoding.UTF8.GetBytes("live"));
            await store.PutAsync("gone", Encoding.UTF8.GetBytes("dead"));
            await store.DeleteAsync("gone");

            long lenBefore = await memoryStore.GetLengthAsync();

            await store.CompactAsync();

            long lenAfter = await memoryStore.GetLengthAsync();
            Assert.IsTrue(lenAfter <= lenBefore, $"Expected lenAfter <= lenBefore, got {lenAfter} > {lenBefore}");

            byte[]? keep = await store.GetAsync("keep");
            Assert.IsNotNull(keep);
            Assert.AreEqual("live", Encoding.UTF8.GetString(keep!));

            byte[]? gone = await store.GetAsync("gone");
            Assert.IsNull(gone);

            await store.DisposeAsync();
        }

        [TestMethod]
        public async Task PutOverwriteLastWinsAfterCompact()
        {
            MemoryAppendOnlyStoreProvider memoryStore = new ();
            EncryptedEntryStore store = await CreateStoreAsync(memoryStore);

            string id = "k";
            await store.PutAsync(id, Encoding.UTF8.GetBytes("v1"));
            await store.PutAsync(id, Encoding.UTF8.GetBytes("v2"));

            byte[]? now = await store.GetAsync(id);
            Assert.AreEqual("v2", Encoding.UTF8.GetString(now!));

            await store.CompactAsync();

            byte[]? after = await store.GetAsync(id);
            Assert.AreEqual("v2", Encoding.UTF8.GetString(after!));

            await store.DisposeAsync();
        }
    }

    #endregion
}