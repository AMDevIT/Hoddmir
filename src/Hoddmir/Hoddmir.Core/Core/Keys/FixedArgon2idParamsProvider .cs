namespace Hoddmir.Core.Core.Keys
{
    public sealed class FixedArgon2idParamsProvider(Argon2idParams p) 
        : IArgon2idParamsProvider
    {
        #region Fields

        private readonly Argon2idParams currentP = p;

        #endregion

        #region Properties

        public Argon2idParams? Parameters => this.currentP;

        #endregion

        #region Methods

        public Argon2idParams GetParameters()
        {
            return this.currentP;
        }

        public override string ToString()
        {
            return "FixedArgon2idParamsProvider: " + this.currentP.ToString();
        }

        #endregion
    }
}
