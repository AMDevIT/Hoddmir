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
        #region Consts

        /// <summary>
        /// Password used to create test-only stores. This is not a real password and should not 
        /// be used for anything other than testing.
        /// </summary>
        private const string TestPassword = "test-password123.";
        private const string TestFilePath = "test-store.dat";
        private const string RandomTestFilePath = "test-store-r2.dat";

        #endregion

        #region Fields

        private static IArgon2idParamsProvider fastArgon = new FixedArgon2idParamsProvider(new Argon2idParams(32 * 1024, 2, 2));

        #endregion

        #region Methods

        public async Task CreateTestStoreAsync(bool useFastArgon = false, 
                                               CancellationToken cancellationToken = default)
        {
            if (File.Exists(TestFilePath))
                File.Delete(TestFilePath);

            IArgon2idParamsProvider argon2Provider;
            ChaCha20Poly1305Provider aead = new();
            await using FileAppendOnlyStoreProvider provider = new (TestFilePath);

            if (useFastArgon)
                argon2Provider = fastArgon;
            else
                argon2Provider = new CalibratingArgon2idParamsProvider();

            await using EncryptedEntryStore store = await CreateStoreAsync(provider, 
                                                                           aead, 
                                                                           TestPassword, 
                                                                           argon2Provider, 
                                                                           cancellationToken);

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

            IArgon2idParamsProvider argon2Provider;
            ChaCha20Poly1305Provider aead = new();
            await using  FileAppendOnlyStoreProvider provider = new(RandomTestFilePath);

            if (useFastArgon)
                argon2Provider = fastArgon;
            else
                argon2Provider = new CalibratingArgon2idParamsProvider();

            await using EncryptedEntryStore store = await CreateStoreAsync(provider,
                                                                           aead,
                                                                           TestPassword,
                                                                           argon2Provider,
                                                                           cancellationToken);

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

        private static Task<EncryptedEntryStore> CreateStoreAsync(IAppendOnlyStoreProvider store, 
                                                                  IAEADProvider aead,
                                                                  string password,
                                                                  IArgon2idParamsProvider argonProvider,
                                                                  CancellationToken cancellationToken = default)
        {
            if (store is IAtomicReplace atomicReplace)
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                Task<EncryptedEntryStore> openedEncryptedStore = EncryptedEntryStore
                                                              .Configure()
                                                              .WithPassword(passwordBytes)
                                                              .WithDekArgon2id(argonProvider)
                                                              .WithAead(aead)
                                                              .OpenAsync(store,
                                                                         atomicReplace,
                                                                         cancellationToken);
                return openedEncryptedStore;
            }
            else
                throw new ArgumentException("The provided store does not support atomic replace, " +
                                            "which is required for opening an encrypted store.", 
                                            nameof(store));
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
