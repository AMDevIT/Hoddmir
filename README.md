# Hoddmir

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![.NET](https://img.shields.io/badge/.NET-9.0%20%7C%2010.0-purple)](https://dotnet.microsoft.com)

**Hoddmir** is a portable, offline-first encrypted blob storage library for .NET.

The library maps string keys to binary values and provides put, get, delete and list operations. The built-in backends keep the encrypted data in a local file or in process memory. A password protects access to the store.

```
key (string)  →  value (byte[])   encrypted with AES-256-GCM / ChaCha20-Poly1305 / AES-CTR+HMAC
```

---

## Use cases

- Encrypt application configuration or cached blobs on disk.
- Move an encrypted archive between compatible applications that share the store credentials and AEAD configuration.
- Use the in-memory backend for transient data or tests that do not require file I/O.

---

## Cryptographic design

### Record encryption

Each record is encrypted with a 256-bit key derived from the store's **Data Encryption Key (DEK)** using one of three AEAD algorithms:

| Algorithm | Notes |
|---|---|
| **ChaCha20-Poly1305** | Provided by the Bouncy Castle add-on. |
| **AES-256-GCM** | Uses the .NET runtime implementation where supported. The Bouncy Castle add-on also provides an explicit AES-GCM implementation. |
| **AES-256-CTR + HMAC-SHA-256** | Encrypt-then-MAC with HKDF-SHA-256 subkeys. The MAC covers the 64-bit little-endian lengths of the AAD and ciphertext, followed by the AAD, nonce and ciphertext. |

The test suite includes published vectors for ChaCha20-Poly1305 (RFC 8439), AES-GCM (NIST SP 800-38D) and HKDF-SHA-256 (RFC 5869). The AES-CTR + HMAC construction has an independently computed test vector.

### DEK protection

The DEK is wrapped in the store header using **Argon2id**.

Two independent Argon2id derivations protect the store:

| Derivation | Purpose | Parameters |
|---|---|---|
| **Session KEK** | Encrypts the entire header blob | `password + salt(on-disk) + sessionIterations(caller) + SessionMemKiB=64MiB(hardcoded)` |
| **DEK KEK** | Encrypts the DEK inside the header | `password + DekArgonSalt(in header) + DekArgonParams(in header)` |

The DEK KEK parameters are stored inside the encrypted header and can be changed during key rotation. Hoddmir accepts up to 512 MiB, 10 iterations and 16 lanes for this derivation, with at least 8 KiB per lane. Callers supply the session parameters (`sessionIterations`, `sessionSaltLen`) each time they open the store. An offline attacker can test a password guess against the outer header tag with one session Argon2id derivation.

### Nonce safety

Each write or rewrite generates a fresh 32-byte random salt. HKDF-SHA-256 derives the record key from the DEK, the salt and the UTF-8 context `Hoddmir/0x01/record`. Under that key, the prefix uses the 12-byte zero nonce and the payload uses the 12-byte nonce ending in `01` with all other bytes zero. Reopening a store requires no nonce counter.

### Memory safety

The DEK is held in a GC-pinned managed array (`SensitiveBytes`) and cleared on disposal. The record codec also clears its temporary keys and plaintext buffers. The store persists the wrapped DEK.

---

## Packages

| Package | Description |
|---|---|
| `Hoddmir` | Encrypted store, file and memory backends, AES-GCM and AES-CTR + HMAC providers. |
| `Hoddmir.BouncyCastle` | Optional ChaCha20-Poly1305 and AES-GCM providers backed by Bouncy Castle. |

---

## Getting started

### Installation

```bash
dotnet add package Hoddmir
# Optional: adds the Bouncy Castle AEAD providers
dotnet add package Hoddmir.BouncyCastle
```

### Basic usage — file-backed store

```csharp
using Hoddmir.Core.Encryption.AEAD;
using Hoddmir.Storage;
using Hoddmir.Storage.Providers;
using System.Text;

await using var fileStore = new FileAppendOnlyStoreProvider("vault.bin", FileMode.CreateNew);

await using var store = await EncryptedEntryStore.Configure()
    .WithPassword(Encoding.UTF8.GetBytes("my-strong-password"))
    .WithAead(new AesGcmProvider())
    // Optional: override session credentials (must match on every reopen)
    // .WithSessionIterations(3)
    // .WithSessionSaltLength(32)
    .CreateAsync(fileStore, fileStore);

// Store a blob
await store.PutAsync("images/avatar.png", File.ReadAllBytes("avatar.png"));
await store.PutAsync("config/api-key",    Encoding.UTF8.GetBytes("sk-abc123"));

// Retrieve a blob
byte[]? blob = await store.GetAsync("config/api-key");

// List all stored keys
IReadOnlyCollection<string> keys = store.ListIds();

// List by prefix
var imageKeys = keys.Where(k => k.StartsWith("images/", StringComparison.Ordinal));

// Delete a blob
await store.DeleteAsync("config/api-key");

// Verify the header and records
VerifyResult result = await store.VerifyAsync();
if (!result.IsHealthy)
    Console.WriteLine(result);
```

### In-memory store (testing or transient use)

The in-memory provider uses the same store API and keeps the encrypted log in memory.

```csharp
using Hoddmir.Core.Encryption.AEAD;
using Hoddmir.Storage;
using Hoddmir.Storage.Providers;
using System.Text;

var memStore = new MemoryAppendOnlyStoreProvider();

await using var store = await EncryptedEntryStore.Configure()
    .WithPassword(Encoding.UTF8.GetBytes("my-strong-password"))
    .WithAead(new AesCtrHmacSha256Provider())
    .CreateAsync(memStore, memStore);

await store.PutAsync("session/token", Encoding.UTF8.GetBytes("Bearer eyJ..."));
```

### Reopen an existing store

To reopen a store, use the same password, session parameters and a compatible AEAD provider.
`OpenAsync` requires an initialized vault. To create one, use `CreateAsync` on an empty backend. The file backend opens existing files by default. Pass `FileMode.CreateNew` to create a file at an unused path. The backend keeps a sibling `.lock` file to exclude another writer during file replacement. Keep this lock file in place while any backend for the vault may be open.

```csharp
// First session
await using (var fileStore = new FileAppendOnlyStoreProvider("vault.bin", FileMode.CreateNew))
{
    await using var store = await EncryptedEntryStore.Configure()
        .WithPassword(password)
        .WithAead(new AesGcmProvider())
        .CreateAsync(fileStore, fileStore);

    await store.PutAsync("report/q3.pdf", pdfBytes);
}

// Later session
await using var fileStore2 = new FileAppendOnlyStoreProvider("vault.bin");
await using var store2 = await EncryptedEntryStore.Configure()
    .WithPassword(password)
    .WithAead(new AesGcmProvider())
    .OpenAsync(fileStore2, fileStore2);

byte[]? pdf = await store2.GetAsync("report/q3.pdf");
```

### Fixed Argon2id parameters

By default, Argon2id uses 128 MiB, three iterations and parallelism four to wrap the DEK. Pass a parameter provider to customize these settings. `CalibratingArgon2idParamsProvider` is available when you want to calibrate the parameters for a device.

```csharp
using Hoddmir.Core.Keys;

Argon2idParams parameters = new(MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2);
FixedArgon2idParamsProvider argonParams = new(parameters);

await using var store = await EncryptedEntryStore.Configure()
    .WithPassword(passwordBytes)
    .WithDekArgon2id(argonParams)
    .WithAead(new AesGcmProvider())
    .CreateAsync(fileStore, fileStore);
```

### Key rotation

Rotate the DEK at any time without closing the store. All live blobs are re-encrypted under a fresh DEK and the resulting file replaces the previous one atomically. Rotation requires the current password.

```csharp
// Rotate DEK, keeping the same password
await store.RotateDekAsync(currentPasswordUtf8: Encoding.UTF8.GetBytes("my-strong-password"));

// Rotate DEK and change the password at the same time
await store.RotateDekAsync(currentPasswordUtf8: Encoding.UTF8.GetBytes("old-password"),
                           newPasswordUtf8:     Encoding.UTF8.GetBytes("new-stronger-password"));

// Rotate DEK and change session parameters (all three credentials change)
await store.RotateDekAsync(currentPasswordUtf8: Encoding.UTF8.GetBytes("old-password"),
                           newPasswordUtf8:     Encoding.UTF8.GetBytes("new-password"),
                           newSessionIters:     4,
                           newSessionSaltLen:   64);
```

### Compaction

The store is append-only. A delete appends a tombstone, and an overwrite appends the new value. Call `CompactAsync` to reclaim the space occupied by old records.

```csharp
await store.CompactAsync();
```

### Using AEAD providers directly

Hoddmir's AEAD providers can be used independently of the store to encrypt arbitrary blobs.

```csharp
using Hoddmir.Core.Encryption.AEAD;
using System.Security.Cryptography;
using System.Text;

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

Both packages target `net9.0` and `net10.0`. `AesGcmProvider` depends on the runtime's AES-GCM support. The `Hoddmir.BouncyCastle` package exposes `AesGcmBouncyCastleProvider` and `ChaCha20Poly1305Provider` in the `Hoddmir.BouncyCastle.Encryption.AEAD` namespace. Select either explicitly with `WithAead`.

---

## Security model and limits

Hoddmir encrypts keys and values at rest and authenticates each record at its stored offset. File size and changes in size across snapshots remain visible. Resistance to offline password guessing depends on the password and the session Argon2id parameters.

- **Rollback.** The authenticated chain prevents splicing records from separate histories. To reject an older complete copy or a valid prefix after reopening, save the 32-byte result of `GetCheckpointAsync` in trusted storage and pass it to `OpenAtCheckpointAsync`. The checkpoint must match the authenticated log prefix when recovering an incomplete tail. Coordinate checkpoint updates with successful writes, compaction and rotation. The trusted storage must itself resist rollback.
- **Corruption.** A complete record that fails authentication blocks normal reopening, even when a later record supersedes it.
- **Process memory.** An open store holds the DEK in memory and returns plaintext to its caller. A compromised process, memory dump or swap file may expose sensitive material.
- **Deletion.** Older values remain in the encrypted log until compaction. Previous copies and backups retain their contents.

The store format and AES-CTR + HMAC construction have yet to undergo an independent security audit.

---

## File format

The current version is `0x01`. The magic value, version and algorithm ID are inside the encrypted header. The file also contains public salts, ciphertext and authentication tags. Recreate vaults produced by earlier development builds.

### On-disk layout

```
[Salt(SessionSaltLen)]
[EncryptedHeaderBlob(512 bytes)]
[Record...]
```

The session KEK encrypts the 512-byte header following the session salt and authenticates the UTF-8 string `Hoddmir/0x01/header` as associated data. The DEK wrapper authenticates `Hoddmir/0x01/dek` as associated data. The records use keys derived from the DEK.

### Header plaintext (decrypted, padded to 496 bytes with random data)

```
Magic(4)="EES1" | Ver(1)=0x01 | AeadId(1)
DekNonce(12)    | EncDek(32)   | DekTag(16)
DekArgonSalt(16)| DekArgonMemKiB(4) | DekArgonIters(4) | DekArgonPar(4)
```

### Record layout

```
[RecordSalt(32)]
[EncPrefix(29)]    — encrypted 13-byte prefix + 16-byte tag
[PaddedCt(var)]    — encrypted payload including padding
[PayloadTag(16)]
```

Prefix plaintext (13 bytes):
```
Op(1) | KeyLen(4,LE) | ContentLen(4,LE) | PaddedLen(4,LE)
```

Payload plaintext:
```
keyBytes(KeyLen) || value(ContentLen-KeyLen) || random_padding(PaddedLen-ContentLen)
```

Operation `0` is a put and `1` is a tombstone with an empty value. The prefix authenticates the absolute record offset as an 8-byte little-endian integer followed by the SHA-256 digest of the previous serialized record. The first record uses the SHA-256 digest of the session salt and encrypted header. The payload authenticates the encrypted prefix and its tag as associated data.

### Index and recovery

Each mutation appends one record. Opening the store authenticates records in file order and rebuilds the in-memory index. A complete record that fails authentication prevents opening. If the final record is incomplete, the store exposes the preceding records and reports the tail via `VerifyAsync`. Call `CompactAsync` to remove the incomplete tail before appending again.

`VerifyAsync` checks that the header and committed log match the open store. A changed header sets `IsHeaderCorrupted`. A valid prefix that differs from the committed log sets `IsLogChanged`. An incomplete header is reported as truncation at offset zero. Verification stops at the first broken link in the log. Compaction and rotation reject a changed header or corrupt committed history. `GetAsync` throws `InvalidDataException` when an indexed record fails validation.

Before appending, the store checks the header and last committed record. The backend then checks the expected offset atomically with the append. Use `VerifyAsync` to check the full history.

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
    public Task AppendAsync(ReadOnlyMemory<byte> data, long expectedOffset, CancellationToken ct = default) { ... }
    public Task       FlushAsync(bool hard = false, CancellationToken ct = default) { ... }
    public Task       ReplaceWithAsync(Func<Stream, Task> buildNew, CancellationToken ct = default) { ... }
}
```

`AppendAsync` writes at the end of the store and returns the actual starting offset of that write. Use one open `EncryptedEntryStore` instance per backing store.
---

## Contributing

Pull requests are welcome. For significant changes, please open an issue first to discuss what you would like to change.

---

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
