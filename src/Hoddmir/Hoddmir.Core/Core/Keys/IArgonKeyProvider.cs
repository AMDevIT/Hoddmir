namespace Hoddmir.Core.Core.Keys
{
    public interface IArgonKeyProvider
    {
        #region Consts

        public const int DefaultArgonKeyLength = 32;

        #endregion

        #region Methods

        byte[] DeriveKekArgon2id(byte[] password,
                                 byte[] salt,
                                 int memKiB,
                                 int iters,
                                 int parallelism,
                                 int keyLength = DefaultArgonKeyLength);

        #endregion
    }
}
