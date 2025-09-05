using Konscious.Security.Cryptography;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Hoddmir.Core.Core.Keys.Calibration
{

    public sealed class CalibratingArgon2idParamsProvider 
        : IArgon2idParamsProvider
    {
        #region Consts

        private const int Kilobyte = 1024;

        #endregion

        #region Fields

        private readonly TimeSpan target; 
        private readonly int maxMemMiB;
        private Argon2idParams? changedParameters = null;

        #endregion

        #region Properties

        public Argon2idParams? Parameters => this.changedParameters;

        #endregion

        #region .ctor

        public CalibratingArgon2idParamsProvider(TimeSpan target, int maxMemMiB = 512)
        { 
            this.target = target; 
            this.maxMemMiB = maxMemMiB; 
        }

        #endregion

        public Argon2idParams GetParameters()
        {
            int par = Math.Clamp(Environment.ProcessorCount, 1, 4);
            int memMiB = 32; int iters = 2;

            byte[] pwd = new byte[16]; 
            byte[] salt = new byte[16];

            RandomNumberGenerator.Fill(pwd);
            RandomNumberGenerator.Fill(salt);

            try
            {
                while (memMiB <= this.maxMemMiB)
                {
                    Stopwatch sw = Stopwatch.StartNew();
                    using (Argon2id argon = new (pwd) 
                    { 
                        Salt = salt, 
                        MemorySize = memMiB * Kilobyte, 
                        Iterations = iters, 
                        DegreeOfParallelism = par 
                    })

                    _ = argon.GetBytes(32);

                    sw.Stop();

                    if (sw.Elapsed >= this.target) 
                        break;

                    if (memMiB < 256) 
                        memMiB *= 2; 
                    else 
                        iters++;

                    if (iters > 6) 
                        break;
                }
            }
            finally 
            { 
                CryptographicOperations.ZeroMemory(pwd); 
            }

            return new Argon2idParams(memMiB * Kilobyte, iters, par);
        }
    }

}
