# Hoddmir

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-9.0%20%7C%2010.0-purple)](https://dotnet.microsoft.com)
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
| **ChaCha20-Poly1305** *(recommended)* | Fast, no timing side-channels, available on all targets. |
| **AES-256-GCM** | Requires .NET 9+. |
| **AES-256-CTR + HMAC-SHA-256** | Encrypt-then-MAC construction. Subkeys derived via HKDF-SHA-256 (RFC 5869). No hardware dependency. |

All three algorithms are verified against published test vectors: RFC 8439 (ChaCha20-Poly1305), NIST SP 800-38D (AES-GCM), and RFC 5869 (HKDF-SHA-256).

### DEK protection

The DEK is wrapped in the store header using **Argon2id** (the only supported mode in v0x04).

Two independent Argon2id derivations protect the store:

| Derivation | Purpose | Parameters |
|---|---|---|
| **Session KEK** | Encrypts the entire header blob | `password + salt(on-disk) + sessionIterations(caller) + SessionMemKiB=64MiB(hardcoded)` |
| **DEK KEK** | Encrypts the DEK inside the header | `password + DekArgonSalt(in header) + DekArgonParams(in header)` |

The DEK KEK parameters are stored inside the encrypted header and can be rotated independently. Session parameters (`sessionIterations`, `sessionSaltLen`) are never stored on disk — they form part of the credentials required to open the store.

> **Platform-specific modes** (Windows Hello TPM, Apple Secure Enclave) are planned as optional extension packages. `WindowsDPAPI` and `PasswordPBKDF2` from v0x03 have been removed.

### Nonce safety

Two independent nonce schemes are used:

- **Record prefix nonce:** `Token[0..12]` — 12 bytes of CSPRNG entropy unique per record. No shared component between records.
- **Payload nonce:** `NoncePrefix(4, fixed per store) ‖ Seq_BE(8)` — uniqueness guaranteed by the monotonic `uint64` sequence counter for up to 2⁶⁴ writes per store.

Both schemes eliminate nonce reuse by construction.

### Memory safety

Sensitive material (DEK, nonce prefix, derived subkeys) is held in GC-pinned managed arrays (`SensitiveBytes`) and zeroed with `CryptographicOperations.ZeroMemory` on disposal. Passwords are never stored — only the DEK, wrapped with the password-derived key, is persisted.

---

## Packages

| Package | Description |
|---|---|
| `Hoddmir` | Core library. AES-GCM (.NET 9+), AES-CTR+HMAC (all targets), `EncryptedEntryStore`. |
| `Hoddmir.BouncyCastle` | Optional add-on. ChaCha20-Poly1305. |

---

## Getting started

### Installation

```bash
dotnet add package Hoddmir
# Recommended: adds ChaCha20-Poly1305
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
    // Optional: override session credentials (must match on every reopen)
    // .WithSessionIterations(3)
    // .WithSessionSaltLength(32)
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

// Verify integrity of all records (non-destructive)
VerifyResult result = await store.VerifyAsync();
if (!result.IsHealthy)
    Console.WriteLine(result); // "Store UNHEALTHY: 1/5 OK, 1 corrupted, 0 truncated."
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
    .WithDekArgon2id(argonParams)
    .WithAead(new ChaCha20Poly1305Provider())
    .OpenAsync(fileStore, fileStore);
```

### Key rotation

Rotate the DEK at any time without closing the store. All live blobs are re-encrypted with a fresh key and a new nonce prefix atomically. The current password must be provided to authenticate the rotation.

```csharp
// Rotate DEK, keeping the same password
await store.RotateDekAsync(
    currentPasswordUtf8: Encoding.UTF8.GetBytes("my-strong-password"));

// Rotate DEK and change the password at the same time
await store.RotateDekAsync(
    currentPasswordUtf8: Encoding.UTF8.GetBytes("old-password"),
    newPasswordUtf8:     Encoding.UTF8.GetBytes("new-stronger-password"));

// Rotate DEK and change session parameters (all three credentials change)
await store.RotateDekAsync(
    currentPasswordUtf8: Encoding.UTF8.GetBytes("old-password"),
    newPasswordUtf8:     Encoding.UTF8.GetBytes("new-password"),
    newSessionIters:     4,
    newSessionSaltLen:   64);
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
| iOS / Android (.NET 9+) | ✅ via BouncyCastle | ✅ via BouncyCastle¹ | ✅ |

¹ Requires the `Hoddmir.BouncyCastle` package. `AesGcmProvider` throws `PlatformNotSupportedException` at construction if no fallback is registered and the runtime is older than .NET 9.

---

## Security and forensic resistance

### Threat model summary

This is the expected threat model summary:

| Scenario | Resistance | Notes |
|---|---|---|
| File at rest, device off | ✅ Very high | AES-256 / ChaCha20-Poly1305 — no known practical attack |
| File at rest, store closed, device on | ✅ Very high | No DEK in memory — equivalent to VeraCrypt with a dismounted volume |
| Password brute force | ✅ High | Depends on password strength and Argon2id cost |
| Forensic file analysis without memory | ✅ Very high | Fully opaque format — no magic bytes, no plaintext structure, statistically indistinguishable from random noise |
| Memory forensics, store open | 🟡 Medium | DEK lives in the process during an open session — structural limitation of managed runtimes |
| Swap / pagefile during active session | 🟡 Medium | OS may page process memory to disk; not controllable from managed code without kernel privileges |
| Key name confidentiality | ✅ High | Blob keys are stored only in the encrypted index record; not visible in plaintext on disk |
| Nation-state, device off or store closed | ✅ Very high | No memory to dump — same posture as VeraCrypt with a dismounted volume |
| Nation-state, store open on a live device | 🔴 Low | DEK is in memory; memory forensics, cold boot, or hypervisor introspection become viable |

> **Disclaimer:** without a formal security audit the threat model above cannot be guaranteed. It is based on the authors' knowledge of common attack vectors and cryptographic best practices.

### Notes

**The cryptography is sound.** ChaCha20-Poly1305 and AES-256-GCM are the same algorithms used by Signal, WhatsApp, and NSA Suite B / CNSA. No practical cryptanalytic attack exists against correctly implemented 256-bit AEAD. All algorithms are verified against published test vectors (RFC 8439, NIST SP 800-38D, RFC 5869).

**Memory forensics is the main exposure.** The DEK is resident in process memory for the duration of an open store session. A memory dump of the process (`ProcDump`, `WinPmem`, OS crash dump) can expose the DEK even with `SensitiveBytes` and `ZeroMemory` in place. This is a structural limitation of .NET managed runtimes — the JIT and GC can materialise intermediate values in registers or on the stack before zeroing occurs. VeraCrypt mitigates this using kernel drivers and non-pageable memory; Hoddmir cannot do this without elevated privileges.

**Key names are encrypted.** As of v0x04, record IDs are stored only in the encrypted index record — they do not appear in plaintext on disk. An investigator without the password cannot observe key names, values, or the number of records. The write timeline (number of records written over time) can still be inferred from file size growth if the attacker has access to successive snapshots of the file.

**The real attack surface at nation-state level is never the ciphertext.** Keyloggers, compromised devices, supply chain attacks, and coercive access to the password are the practical vectors. No cryptographic library protects against these — Hoddmir included.

**What would raise the bar further.** The main remaining exposure for forensic resistance is keeping the DEK resident in memory for the duration of an open store session. Deriving the DEK fresh from the password on each operation would eliminate this — at a significant performance cost. This is not necessary for Hoddmir's primary use case as an application-level blob store.

---

## File format

The current version is `0x04`. The file is **fully opaque** — there are no plaintext magic bytes, no visible structure, and no identifiable headers. The file is statistically indistinguishable from random noise.

### On-disk layout

```
[Salt(SessionSaltLen)]
[EncryptedHeaderBlob(512 bytes)]
[Record...]
```

The salt length is a caller-controlled credential (default 16 bytes, max 256). Everything after the salt is encrypted with the session KEK.

### Header plaintext (decrypted, padded to 496 bytes with random data)

```
Magic(4)="EES1" | Ver(1)=0x04 | AeadId(1)
NoncePrefix(4)  | IndexToken(16)
DekNonce(12)    | EncDek(32)   | DekTag(16)
DekArgonSalt(16)| DekArgonMemKiB(4) | DekArgonIters(4) | DekArgonPar(4)
```

### Record layout (all fields opaque from outside)

```
[EncPrefix(45)]    — encrypted 29-byte prefix + 16-byte tag
[Token(16)]        — random opaque handle
[PaddedCt(var)]    — encrypted payload + random padding
[PayloadTag(16)]   — AEAD tag over EncPrefix + PaddedCt
```

EncPrefix plaintext (29 bytes):
```
PreNoise(4) | Op(1) | Seq(8,LE) | KeyLen(4,LE) | CtLen(4,LE) | PaddedCtLen(4,LE) | PostNoise(4)
```

Payload plaintext:
```
keyBytes(KeyLen) || value(CtLen-KeyLen) || random_padding(PaddedCtLen-CtLen)
```

The `AeadId` and all key material are inside the encrypted header. Attempting to open a store with the wrong AEAD provider or wrong credentials fails immediately.

### Encrypted index

Every write appends a data record followed by an **encrypted index record**. The index maps opaque token hex strings to human-readable IDs. Record IDs never appear in plaintext on disk. `ListIds()` returns IDs from the in-memory map populated at open time.

### Credentials

Opening a store requires three independent values:

| Credential | Default | Notes |
|---|---|---|
| `password` | — (required) | Raw UTF-8 bytes |
| `sessionIterations` | `2` | Argon2id iterations for the header KEK |
| `sessionSaltLen` | `16` | Length of the random salt at the start of the file |

All three must match. The salt length and session iterations are **never stored on disk** — they are part of the credentials.

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
---

## Contributing

Pull requests are welcome. For significant changes, please open an issue first to discuss what you would like to change.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).