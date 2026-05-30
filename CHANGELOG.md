# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.9.0] — 2026-05-30

### Initial release

Hoddmir is a portable, offline-first encrypted blob storage library for .NET.
This is the first public release, intended for community feedback before a stable 1.0.0 API.

### Added

- `EncryptedEntryStore` — append-only encrypted key-value store with file and in-memory backends
- Fluent builder API: `EncryptedEntryStore.Configure().WithPassword(...).WithAead(...).OpenAsync(...)`
- `PutAsync`, `GetAsync`, `DeleteAsync`, `ListIds`, `CompactAsync`
- `RotateDekAsync` — atomic DEK rotation with optional password change
- Three AEAD providers: `AesGcmProvider` (AES-256-GCM), `ChaCha20Poly1305Provider` (via `Hoddmir.BouncyCastle`), `AesCtrHmacSha256Provider` (AES-256-CTR + HMAC-SHA-256, Encrypt-then-MAC)
- `AeadExtensions` — high-level `Encrypt` / `TryDecrypt` helpers for direct provider use
- `AeadProviderRegistry` — global fallback registry; optional packages register via `[ModuleInitializer]`
- `AesGcmBouncyCastleProvider` — automatic AES-GCM fallback for .NET 8 via `Hoddmir.BouncyCastle`
- Three `KeyProtectionMode` options: `PasswordArgon2id` (recommended), `PasswordPBKDF2`, `WindowsDPAPI`
- `CalibratingArgon2idParamsProvider` — auto-calibrates Argon2id parameters to ~500 ms on the current device; thread-safe via `Lazy<Task<T>>`
- `FixedArgon2idParamsProvider` — fixed parameters for tests and constrained environments
- Deterministic nonce construction: `NoncePrefix(8 random bytes) ‖ Seq_BE(4 bytes)` — uniqueness guaranteed up to ~4 billion writes per store
- `SensitiveBytes` — GC-pinned managed buffer, zeroed on disposal via `CryptographicOperations.ZeroMemory`
- `FileAppendOnlyStoreProvider` and `MemoryAppendOnlyStoreProvider` — both thread-safe via `SemaphoreSlim`
- Store file format v0x03 with `AeadAlgorithmId` in the fixed header — provider mismatch detected at open time
- Known-answer tests against RFC 8439 (ChaCha20-Poly1305), NIST SP 800-38D (AES-GCM), RFC 5869 (HKDF-SHA-256)

### Security

- Wrong password on `OpenAsync` now throws `CryptographicException` instead of silently opening with a corrupted DEK
- HKDF-SHA-256 subkey derivation (RFC 5869 compliant) with optional explicit salt; low-entropy IKM warning via `ILogger`

### Known limitations

- Blob key names are stored in plaintext — values are encrypted, metadata is not
- DEK is resident in process memory for the duration of an open session (structural limitation of managed runtimes)
- `WindowsDPAPI` mode does not add an additional AEAD layer over the DEK — planned for a future release alongside broader cross-platform key protection improvements
- No formal security audit has been performed