# Hoddmir

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0-purple)](https://dotnet.microsoft.com)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20iOS%20%7C%20Android-lightgrey)]()

**Hoddmir** is a portable, offline-first encrypted blob storage library for .NET.

Think of it as an Azure Blob Storage or Amazon S3 — a flat namespace of arbitrary string keys mapped to arbitrary binary values, with Put / Get / Delete / List — except that every blob is individually encrypted at rest, the entire store is protected by a password, and it runs everywhere .NET runs with zero native dependencies and zero data leaving the device.

```
key (string)  →  value (byte[])   encrypted with AES-256-GCM / ChaCha20-Poly1305 / AES-CTR+HMAC
```

---

## Why Hoddmir?

Most .NET applications that need to store secrets or encrypted blobs end up choosing between:

- **Plain files or SQLite** — fast and portable, but unencrypted.
- **Platform APIs** (Windows DPAPI, iOS Keychain, Android Keystore) — encrypted, but not cross-platform.
- **Cloud blob storage** (Azure, S3, GCS) — available everywhere, but requires connectivity, authentication infrastructure, and sends data to third-party servers.
- **SQLCipher** — encrypted SQLite, powerful, but requires native binaries and SQL overhead.
- **Volume encryption** (VeraCrypt, LUKS) — strong, but requires kernel drivers, admin privileges, and doesn't work on mobile or in sandboxed processes.

Hoddmir fills the gap: **encrypted, portable, embedded, offline-first**.

| | Hoddmir | Azure Blob | SQLCipher | VeraCrypt |
|---|---|---|---|---|
| Encrypted at rest | ✅ | ✅ (server-side) | ✅ | ✅ |
| Works offline | ✅ | ❌ | ✅ | ✅ |
| No native dependencies | ✅ | ✅ | ❌ | ❌ |
| iOS / Android / Unity | ✅ | ✅ | ❌ | ❌ |
| No data leaves device | ✅ | ❌ | ✅ | ✅ |
| No admin / kernel rights | ✅ | ✅ | ✅ | ❌ |
| Embedded in your app | ✅ | ❌ | ✅ | ❌ |
| Key-value blob model | ✅ | ✅ | ❌ (SQL) | ❌ (filesystem) |

---

## Use cases

- **Credential vault** — store API keys, tokens, passwords, certificates inside a desktop or mobile app.
- **Offline secrets storage** — device-local encrypted configuration that never touches a server.
- **Encrypted cache** — cache sensitive API responses locally with individual per-record encryption.
- **Portable encrypted archive** — a self-contained encrypted file that can be moved between machines and opened with a password, without any installed software beyond your app.
- **In-process test doubles** — swap the file backend for the in-memory provider in tests, with identical semantics and full encryption.

---

## Cryptographic design

### Record encryption

Each blob is encrypted with a 256-bit **Data Encryption Key (DEK)** using one of three AEAD algorithms:

| Algorithm | Notes |
|---|---|
| **ChaCha20-Poly1305** *(recommended)* | Fast, no timing side-channels, available on all targets including .NET 8 via the `Hoddmir.BouncyCastle` package. |
| **AES-256-GCM** | Requires .NET 9+ or the `Hoddmir.BouncyCastle` package for .NET 8 fallback. |
| **AES-256-CTR + HMAC-SHA-256** | Encrypt-then-MAC construction. Subkeys derived via HKDF-SHA-256 (RFC 5869). No hardware dependency. |

All three algorithms are verified against published test vectors: RFC 8439 (ChaCha20-Poly1305), NIST SP 800-38D (AES-GCM), and RFC 5869 (HKDF-SHA-256).

### DEK protection

The DEK is wrapped in the store header using your chosen `KeyProtectionMode`:

| Mode | Notes |
|---|---|
| **`PasswordArgon2id`** *(recommended)* | Argon2id KDF. Parameters auto-calibrated to ~500 ms on the current device at store creation. |
| **`PasswordPBKDF2`** | PBKDF2-HMAC-SHA-256 with 600 000 iterations. |
| **`WindowsDPAPI`** | OS account identity. Windows only. |

### Nonce safety

Nonces are `NoncePrefix (8 random bytes, fixed per store) ‖ Seq (4 bytes, big-endian)`. Uniqueness is mathematically guaranteed for up to ~4 billion writes per store — no birthday-bound collision risk regardless of how many records you write.

### Memory safety

Sensitive material (DEK, nonce prefix, derived subkeys) is held in GC-pinned managed arrays (`SensitiveBytes`) and zeroed with `CryptographicOperations.ZeroMemory` on disposal. Passwords are never stored — only the DEK, wrapped with the password-derived key, is persisted.

---

## Packages

| Package | Description |
|---|---|
| `Hoddmir` | Core library. AES-GCM (.NET 9+), AES-CTR+HMAC (all targets), `EncryptedEntryStore`. |
| `Hoddmir.BouncyCastle` | Optional add-on. ChaCha20-Poly1305 and AES-GCM on .NET 8 via BouncyCastle. Auto-registers at module load — just reference the package. |

---

## Getting started

### Installation

```bash
dotnet add package Hoddmir
# Recommended: adds ChaCha20-Poly1305 and AES-GCM on .NET 8
dotnet add package Hoddmir.BouncyCastle
```

### Basic usage — file-backed store

```csharp
using Hoddmir.Encryption;
using Hoddmir.Storage;
using Hoddmir.Storage.Providers;
using System.Text;

var fileStore = new FileAppendOnlyStoreProvider("vault.bin");

await using var store = await EncryptedEntryStore.Configure()
    .WithPassword(Encoding.UTF8.GetBytes("my-strong-password"))
    .WithAead(new ChaCha20Poly1305Provider())   // from Hoddmir.BouncyCastle
    .OpenAsync(fileStore, fileStore);

// Store a blob
await store.PutAsync("images/avatar.png", File.ReadAllBytes("avatar.png"));
await store.PutAsync("config/api-key",    Encoding.UTF8.GetBytes("sk-abc123"));

// Retrieve a blob
byte[]? blob = await store.GetAsync("config/api-key");

// List all stored keys
IReadOnlyCollection<string> keys = store.ListIds();

// List by prefix (manual — ListByPrefixAsync coming in a future version)
var imageKeys = keys.Where(k => k.StartsWith("images/"));

// Delete a blob
await store.DeleteAsync("config/api-key");
```

### In-memory store (testing or transient use)

The in-memory provider is a drop-in replacement for the file provider — same encryption, same API, nothing written to disk.

```csharp
using Hoddmir.Storage.Providers;

var memStore = new MemoryAppendOnlyStoreProvider();

await using var store = await EncryptedEntryStore.Configure()
    .WithPassword(Encoding.UTF8.GetBytes("my-strong-password"))
    .WithAead(new AesCtrHmacSha256Provider())
    .OpenAsync(memStore, memStore);

await store.PutAsync("session/token", Encoding.UTF8.GetBytes("Bearer eyJ..."));
```

### Reopen an existing store

Hoddmir stores are persistent. Open the same file with the correct password to access previously written blobs:

```csharp
// First session — create and write
var fileStore = new FileAppendOnlyStoreProvider("vault.bin");
await using (var store = await EncryptedEntryStore.Configure()
    .WithPassword(password)
    .WithAead(new ChaCha20Poly1305Provider())
    .OpenAsync(fileStore, fileStore))
{
    await store.PutAsync("report/q3.pdf", pdfBytes);
}

// Later session — reopen and read
var fileStore2 = new FileAppendOnlyStoreProvider("vault.bin");
await using var store2 = await EncryptedEntryStore.Configure()
    .WithPassword(password)
    .WithAead(new ChaCha20Poly1305Provider())
    .OpenAsync(fileStore2, fileStore2);

byte[]? pdf = await store2.GetAsync("report/q3.pdf");
```

### Fixed Argon2id parameters

The default provider auto-calibrates Argon2id parameters at store creation. For tests or constrained environments (mobile, unit tests), use fixed parameters:

```csharp
using Hoddmir.Keys;

var argonParams = new FixedArgon2idParamsProvider(
    new Argon2idParams(MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2));

await using var store = await EncryptedEntryStore.Configure()
    .WithPassword(passwordBytes)
    .WithArgon2id(argonParams)
    .WithAead(new ChaCha20Poly1305Provider())
    .OpenAsync(fileStore, fileStore);
```

### Key rotation

Rotate the DEK at any time without closing the store. All live blobs are re-encrypted with a fresh key and a new nonce prefix atomically. The current password must be provided to authenticate the rotation.

```csharp
// Rotate, keeping the same password
await store.RotateDekAsync(
    currentPasswordUtf8: Encoding.UTF8.GetBytes("my-strong-password"));

// Rotate and change the password at the same time
await store.RotateDekAsync(
    currentPasswordUtf8: Encoding.UTF8.GetBytes("old-password"),
    newPasswordUtf8:     Encoding.UTF8.GetBytes("new-stronger-password"));
```

### Compaction

The store is append-only. Deleted blobs and overwritten values leave tombstones on disk. Call `CompactAsync` periodically to reclaim space:

```csharp
await store.CompactAsync();
```

### Using AEAD providers directly

Hoddmir's AEAD providers can be used independently of the store to encrypt arbitrary blobs:

```csharp
using Hoddmir.Encryption;

var provider = new AesCtrHmacSha256Provider();

byte[] key      = RandomNumberGenerator.GetBytes(provider.KeySizeBytes);
byte[] aad      = Encoding.UTF8.GetBytes("my-context");
byte[] data     = Encoding.UTF8.GetBytes("secret payload");

// Encrypt — generates nonce internally, returns ct||tag
byte[] combined = provider.Encrypt(key, aad, data, out byte[] nonce);

// Decrypt — returns null if authentication fails
byte[]? recovered = provider.TryDecrypt(key, nonce, aad, combined);
```

---

## Platform support

| Target | `ChaCha20Poly1305Provider` | `AesGcmProvider` | `AesCtrHmacSha256Provider` |
|---|---|---|---|
| .NET 9+ (all platforms) | ✅ via BouncyCastle | ✅ Native | ✅ |
| .NET 8 (all platforms) | ✅ via BouncyCastle | ✅ via BouncyCastle¹ | ✅ |
| iOS / Android (.NET 8+) | ✅ via BouncyCastle | ✅ via BouncyCastle¹ | ✅ |

¹ Requires the `Hoddmir.BouncyCastle` package. `AesGcmProvider` throws `PlatformNotSupportedException` at construction if no fallback is registered and the runtime is older than .NET 9.

---

## File format

Store files are identified by the magic bytes `EES1` and are versioned. The current version is `0x03`.

```
Header:
  [MAGIC(4)="EES1"][VER(1)=0x03][KeyMode(1)][AeadId(1)][HeaderLen(4)][ModePayload][NoncePrefix(8)]

Record:
  byte   Op       (0=Put, 1=Delete)
  int64  Seq      (little-endian)
  int32  KeyLen
  int32  CtLen
  12B    Nonce    = NoncePrefix(8) || Seq_BE(4)
  KeyLen Key      (UTF-8, plaintext)
  CtLen  Ct
  16B    Tag
  
AAD = Op(1) || Seq(8,LE) || KeyLen(4,LE) || CtLen(4,LE)
```

The `AeadId` byte in the fixed header causes Hoddmir to detect and reject a provider mismatch at open time, giving a clear `InvalidOperationException` instead of a silent authentication failure on every record.

> **Note:** blob keys are stored in plaintext in the record. An attacker with access to the file but not the password cannot read blob values, but can observe key names, record count, and write frequency. If key name confidentiality is required for your use case, use opaque keys (e.g. a hash of the logical name).

---

## Extending Hoddmir

### Custom storage backend

Implement `IAppendOnlyStoreProvider` and `IAtomicReplace` to back the store with any storage medium — a database column, a cloud object, a memory-mapped file:

```csharp
public class MyCustomStoreProvider : IAppendOnlyStoreProvider, IAtomicReplace
{
    public Task<long> GetLengthAsync(CancellationToken ct = default) { ... }
    public Task<int>  ReadAtAsync(long offset, Memory<byte> buffer, CancellationToken ct = default) { ... }
    public Task       AppendAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default) { ... }
    public Task       FlushAsync(bool hard = false, CancellationToken ct = default) { ... }
    public Task       ReplaceWithAsync(Func<Stream, Task> buildNew, CancellationToken ct = default) { ... }
}
```

### Custom AEAD provider

Implement `IAEADProvider` and register it in `AeadProviderRegistry` so it can be used as a fallback for existing algorithm IDs, or add a new `AeadAlgorithmId` value for a new algorithm:

```csharp
// In your assembly — auto-registers at module load
internal static class MyProviderInit
{
    [ModuleInitializer]
    internal static void Register()
    {
        AeadProviderRegistry.Register(AeadAlgorithmId.AesGcm,
            () => new MyAesGcmProvider());
    }
}
```

---

## Contributing

Pull requests are welcome. For significant changes, please open an issue first to discuss what you would like to change.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
