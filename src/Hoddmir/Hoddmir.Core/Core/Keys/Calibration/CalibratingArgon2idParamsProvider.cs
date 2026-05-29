using System.Diagnostics;
using System.Security.Cryptography;

namespace Hoddmir.Keys;

/// <summary>
/// <see cref="IArgon2idParamsProvider"/> that calibrates Argon2id parameters to a target
/// wall-clock duration on the current machine.
/// <para>
/// Calibration runs once and is cached. The result is reused for all subsequent calls.
/// Call <see cref="InvalidateCacheAsync"/> to force a new calibration (e.g. after the
/// app returns from background on mobile).
/// </para>
/// <para>Thread-safe: concurrent callers all await the same single calibration task.</para>
/// </summary>
public sealed class CalibratingArgon2idParamsProvider : IArgon2idParamsProvider
{
    private readonly TimeSpan _target;
    private readonly int      _maxMemMiB;

    // Lazy<Task<T>> guarantees a single calibration even under concurrent access.
    private volatile Lazy<Task<Argon2idParams>> _lazy;

    public Argon2idParams? CachedParameters =>
        _lazy.IsValueCreated && _lazy.Value.IsCompletedSuccessfully
            ? _lazy.Value.Result
            : null;

    /// <param name="target">Desired wall-clock time per KDF invocation (default 500 ms).</param>
    /// <param name="maxMemMiB">Upper memory bound in MiB (default 512).</param>
    public CalibratingArgon2idParamsProvider(TimeSpan? target = null, int maxMemMiB = 512)
    {
        _target    = target ?? TimeSpan.FromMilliseconds(500);
        _maxMemMiB = maxMemMiB;
        _lazy      = BuildLazy();
    }

    public Task<Argon2idParams> GetParametersAsync(CancellationToken cancellationToken = default)
        => _lazy.Value;

    /// <summary>
    /// Clears the cached result and schedules a fresh calibration on the next call to
    /// <see cref="GetParametersAsync"/>.
    /// </summary>
    public void InvalidateCache() => _lazy = BuildLazy();

    private Lazy<Task<Argon2idParams>> BuildLazy() =>
        new(() => Task.Run(Calibrate), LazyThreadSafetyMode.ExecutionAndPublication);

    private Argon2idParams Calibrate()
    {
        int parallelism = Math.Clamp(Environment.ProcessorCount, 1, 4);
        int memMiB = 32;
        int iters  = 2;

        byte[] pwd  = new byte[16];
        byte[] salt = new byte[16];
        RandomNumberGenerator.Fill(pwd);
        RandomNumberGenerator.Fill(salt);

        try
        {
            while (memMiB <= _maxMemMiB)
            {
                var p = new Argon2idParams(memMiB * 1024, iters, parallelism);
                var kp = new ArgonKeyProvider();

                var sw = Stopwatch.StartNew();
                _ = kp.DeriveKey(pwd, salt, p, 32);
                sw.Stop();

                if (sw.Elapsed >= _target)
                    break;

                if (memMiB < 256) memMiB *= 2;
                else              iters++;

                if (iters > 6) break;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwd);
        }

        return new Argon2idParams(memMiB * 1024, iters, parallelism);
    }
}
