namespace Hoddmir.Keys;

/// <summary>Immutable set of Argon2id tuning parameters.</summary>
public readonly record struct Argon2idParams(int MemoryKiB, int Iterations, int Parallelism)
{
    public override string ToString() =>
        $"MemoryKiB={MemoryKiB}, Iterations={Iterations}, Parallelism={Parallelism}";
}
