namespace Hoddmir.Core.Core.Keys
{
    public interface IArgon2idParamsProvider 
    {
        #region Properties

        /// <summary>
        /// Cached Argon2id parameters, if available.
        /// </summary>
        Argon2idParams? Parameters
        {
            get;
        }

        #endregion

        #region Methods

        Argon2idParams GetParameters();

        #endregion
    }
}
