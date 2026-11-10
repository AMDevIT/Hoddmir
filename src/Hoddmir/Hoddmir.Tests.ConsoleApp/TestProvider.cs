using Hoddmir.BouncyCastle.Encryption.AEAD;
using Hoddmir.Core.Encryption.AEAD;
using Hoddmir.Core.Keys;
using Hoddmir.Keys;
using Hoddmir.Storage;
using Hoddmir.Storage.Providers;
using Org.BouncyCastle.Asn1;
using System;
using System.Collections.Generic;
using System.Text;
using static Org.BouncyCastle.Asn1.Cmp.Challenge;
using System.Security.Cryptography;

namespace Hoddmir.Tests.ConsoleApp
{
    internal class TestProvider
    {
        #region Const

        /// <summary>
        /// Password used to create test-only stores. This is not a real password and should not 
        /// be used for anything other than testing.
        /// </summary>
        private const string TestPassword = "test-password123.";
        private const string TestFilePath = "test-store.dat";
        private const string RandomTestFilePath = "test-store-r2.dat";

        #endregion

        #region Fields

        private static readonly IArgon2idParamsProvider fastArgon = new FixedArgon2idParamsProvider(new Argon2idParams(32 * 1024, 2, 2));

        #endregion

        #region Methods

        /// <summary>Exercises the encrypted file store from creation through password rotation and reopen.</summary>
        public async Task VerifyFileStoreLifecycleAsync(CancellationToken cancellationToken = default)
        {
            const string key = "keep";
            const string deletedKey = "remove";
            const string reopenedKey = "added-after-reopen";
            const string rotatedKey = "added-after-rotation";
            const string rotatedPassword = "rotated-test-password123.";
            string path = Path.Join(Path.GetTempPath(), $"hoddmir-lifecycle-{Guid.NewGuid():N}.dat");
            byte[] initialValue = "initial value"u8.ToArray();
            byte[] firstUpdate = "updated in the first session"u8.ToArray();
            byte[] secondUpdate = "updated after reopening"u8.ToArray();
            byte[] temporaryValue = "temporary value"u8.ToArray();
            byte[] reopenedValue = "written after reopening"u8.ToArray();
            byte[] rotatedValue = "written after rotation"u8.ToArray();
            AesGcmBouncyCastleProvider reopenAead = new();
            IAEADProvider createAead = AesGcm.IsSupported ? new AesGcmProvider() : reopenAead;

            try
            {
                Console.WriteLine($"Creating the test store with {createAead.Name}.");
                await using (FileAppendOnlyStoreProvider backend = new(path, FileMode.CreateNew))
                await using (EncryptedEntryStore store = await CreateOrOpenStoreAsync(backend, createAead, TestPassword,
                                                                                      fastArgon, cancellationToken, createNew: true))
                {
                    await store.PutAsync(key, initialValue, cancellationToken);
                    await store.PutAsync(deletedKey, temporaryValue, cancellationToken);
                    await VerifyValueAsync(store, key, initialValue, cancellationToken);
                    await store.PutAsync(key, firstUpdate, cancellationToken);
                }

                Console.WriteLine($"Reopening with {reopenAead.Name} to append, update, delete and compact.");
                await using (FileAppendOnlyStoreProvider backend = new(path))
                await using (EncryptedEntryStore store = await CreateOrOpenStoreAsync(backend, reopenAead, TestPassword,
                                                                                      fastArgon, cancellationToken))
                {
                    await VerifyStoreAsync(store, 3, cancellationToken, (key, firstUpdate), (deletedKey, temporaryValue));
                    await store.PutAsync(reopenedKey, reopenedValue, cancellationToken);
                    await store.PutAsync(key, secondUpdate, cancellationToken);
                    await store.DeleteAsync(deletedKey, cancellationToken);
                    if (await store.GetAsync(deletedKey, cancellationToken) is not null)
                        throw new InvalidDataException("The deleted key is still readable.");

                    await VerifyStoreAsync(store, 6, cancellationToken, (key, secondUpdate), (reopenedKey, reopenedValue));
                    await store.CompactAsync(cancellationToken);
                    await VerifyStoreAsync(store, 2, cancellationToken, (key, secondUpdate), (reopenedKey, reopenedValue));

                    Console.WriteLine("Rotating the data key and changing the password.");
                    await store.RotateDekAsync(Encoding.UTF8.GetBytes(TestPassword),
                                               newPasswordUtf8: Encoding.UTF8.GetBytes(rotatedPassword),
                                               newDekArgonParams: fastArgon,
                                               ct: cancellationToken);
                }

                await using (FileAppendOnlyStoreProvider backend = new(path))
                {
                    try
                    {
                        await using (await CreateOrOpenStoreAsync(backend, reopenAead, TestPassword, fastArgon,
                                                                 cancellationToken))
                        {
                            throw new InvalidDataException("The previous password still opens the rotated store.");
                        }
                    }
                    catch (CryptographicException)
                    {
                        Console.WriteLine("The previous password was rejected.");
                    }

                    await using EncryptedEntryStore store = await CreateOrOpenStoreAsync(backend, reopenAead, rotatedPassword,
                                                                                         fastArgon, cancellationToken);
                    await VerifyStoreAsync(store, 2, cancellationToken, (key, secondUpdate), (reopenedKey, reopenedValue));

                    Console.WriteLine("Appending and deleting after reopening with the new password.");
                    await store.PutAsync(rotatedKey, rotatedValue, cancellationToken);
                    await store.DeleteAsync(reopenedKey, cancellationToken);
                }

                Console.WriteLine("Reopening to verify the final state.");
                await using (FileAppendOnlyStoreProvider backend = new(path))
                await using (EncryptedEntryStore store = await CreateOrOpenStoreAsync(backend, reopenAead, rotatedPassword,
                                                                                      fastArgon, cancellationToken))
                {
                    await VerifyStoreAsync(store, 4, cancellationToken, (key, secondUpdate), (rotatedKey, rotatedValue));
                    if (await store.GetAsync(deletedKey, cancellationToken) is not null ||
                        await store.GetAsync(reopenedKey, cancellationToken) is not null)
                        throw new InvalidDataException("A deleted key was restored after reopening.");
                }

                Console.WriteLine("File store lifecycle passed.");
            }
            finally
            {
                File.Delete(path);
                File.Delete(path + ".lock");
            }
        }

        public async Task CreateTestStoreAsync(bool useFastArgon = false, 
                                               CancellationToken cancellationToken = default)
        {
            if (File.Exists(TestFilePath))
                File.Delete(TestFilePath);

            IArgon2idParamsProvider argon2Provider = useFastArgon ? fastArgon : new CalibratingArgon2idParamsProvider();
            ChaCha20Poly1305Provider aead = new();
            await using FileAppendOnlyStoreProvider provider = new(TestFilePath, FileMode.CreateNew);

            await using EncryptedEntryStore store = await CreateOrOpenStoreAsync(provider,
                                                                                 aead,
                                                                                 TestPassword,
                                                                                 argon2Provider,
                                                                                 cancellationToken, createNew: true);

            // Add some test data to the store.
            for (int i = 0; i < 10; i++)
            {
                string key = "TD" + DateTimeOffset.UtcNow.ToUnixTimeSeconds() + i;
                string data = $"Test data {i}";
                await store.PutAsync(key, Encoding.UTF8.GetBytes(data), cancellationToken);
            }
        }

        public async Task CreateTestRandomStoreAsync(bool useFastArgon = false,
                                                     CancellationToken cancellationToken = default)
        {
            if (File.Exists(RandomTestFilePath))
                File.Delete(RandomTestFilePath);

            IArgon2idParamsProvider argon2Provider = useFastArgon ? fastArgon : new CalibratingArgon2idParamsProvider();
            ChaCha20Poly1305Provider aead = new();
            await using  FileAppendOnlyStoreProvider provider = new(RandomTestFilePath, FileMode.CreateNew);

            await using EncryptedEntryStore store = await CreateOrOpenStoreAsync(provider,
                                                                                 aead,
                                                                                 TestPassword,
                                                                                 argon2Provider,
                                                                                 cancellationToken, createNew: true);

            int numberOfEntries = Random.Shared.Next(150);

            // Add some test data to the store.
            for (int i = 0; i < numberOfEntries; i++)
            {
                int randomStringLength = Random.Shared.Next(5, 150);
                int randomDataLength = Random.Shared.Next(20, 200);
                int randomDataType = Random.Shared.Next(0, 3);
                byte[] randomData = RandomNumberGenerator.GetBytes(randomDataLength);
                string key = RandomString(randomStringLength);
                string randomDataString = Convert.ToHexString(randomData);
                string data = randomDataType switch
                {
                    0 => randomDataString,
                    1 => $"Random string index {i}: {RandomString(randomStringLength)}",
                    2 => $"Random number with index {i}: {Random.Shared.Next()}",
                    _ => randomDataString,
                };
                await store.PutAsync(key, Encoding.UTF8.GetBytes(data), cancellationToken);
            }
        }

        /// <summary>Checks that the stored bytes match the expected value.</summary>
        private static async Task VerifyValueAsync(EncryptedEntryStore store, string key, byte[] expectedValue,
                                                   CancellationToken cancellationToken)
        {
            byte[]? actualValue = await store.GetAsync(key, cancellationToken);
            if (actualValue is null || !actualValue.AsSpan().SequenceEqual(expectedValue))
                throw new InvalidDataException($"Unexpected value for key '{key}'.");
        }

        /// <summary>Checks the expected active values and the authenticated record count.</summary>
        private static async Task VerifyStoreAsync(EncryptedEntryStore store, int recordCount, CancellationToken cancellationToken,
                                                   params (string Key, byte[] Value)[] expectedEntries)
        {
            if (store.ListIds().Count != expectedEntries.Length)
                throw new InvalidDataException($"Expected {expectedEntries.Length} active keys.");

            foreach ((string key, byte[] value) in expectedEntries)
                await VerifyValueAsync(store, key, value, cancellationToken);

            VerifyResult result = await store.VerifyAsync(cancellationToken);
            if (!result.IsHealthy || result.TotalRecords != recordCount)
                throw new InvalidDataException($"Expected {recordCount} valid records. {result}");
        }

        /// <summary>Configures and explicitly creates or opens a test vault.</summary>
        private static Task<EncryptedEntryStore> CreateOrOpenStoreAsync(IAppendOnlyStoreProvider store,
                                                                        IAEADProvider aead,
                                                                        string password,
                                                                        IArgon2idParamsProvider argonProvider,
                                                                        CancellationToken cancellationToken,
                                                                        bool createNew = false)
        {
            if (store is not IAtomicReplace atomicReplace)
                throw new ArgumentException("The test backend must support atomic replacement.", nameof(store));

            EncryptedEntryStore.StoreBuilder builder = EncryptedEntryStore.Configure()
                .WithPassword(Encoding.UTF8.GetBytes(password))
                .WithDekArgon2id(argonProvider)
                .WithAead(aead);
            return createNew
                ? builder.CreateAsync(store, atomicReplace, cancellationToken)
                : builder.OpenAsync(store, atomicReplace, cancellationToken);
        }

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string([.. Enumerable.Repeat(chars, length)
                            .Select(s => s[Random.Shared.Next(s.Length)])]);
        }

        #endregion
    }
}
