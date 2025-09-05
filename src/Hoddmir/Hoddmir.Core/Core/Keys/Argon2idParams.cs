namespace Hoddmir.Core.Core.Keys
{
    public readonly record struct Argon2idParams
    {
        #region Properties

        public int MemoryKiB
        {
            get;
            init;
        } 

        public int Iterations
        {
            get;
            init;
        } 

        public int Parallelism
        {
            get;
            init;
        }

        #endregion

        #region .ctor

        public Argon2idParams(int memoryKib, int iterations, int parallelism)
        {
            this.MemoryKiB = memoryKib;
            this.Iterations = iterations;
            this.Parallelism = parallelism;
        }

        #endregion

        #region Methods

        public override string ToString()
        {
            return $"MemoryKiB={MemoryKiB}, Iterations={Iterations}, Parallelism={Parallelism}";
        }

        #endregion
    }
}
