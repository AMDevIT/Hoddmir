using Konscious.Security.Cryptography;

namespace Hoddmir.Core.Core.Keys
{
    public class ArgonKeyProvider
        : IArgonKeyProvider
    {
        #region Consts

        

        #endregion

        #region Methods

        public byte[] DeriveKekArgon2id(byte[] password,
                                        byte[] salt,
                                        int memKiB,
                                        int iters,
                                        int parallelism,
                                        int keyLength = IArgonKeyProvider.DefaultArgonKeyLength)
        {
            using Argon2id argon = new(password)
            {
                Salt = salt,
                MemorySize = memKiB,
                Iterations = iters,
                DegreeOfParallelism = Math.Max(1, parallelism)
            };

            return argon.GetBytes(keyLength);
        }

        #endregion
    }
}
