# Persistence fixes for format 0x01

## Decisions

- The current format remains 0x01. The existing version comparison is the only compatibility check.
- The backends return the actual append offset. The file backend positions the cursor under a semaphore and honors requests to flush to disk. The store serializes mutations and rewrites while coordinating reads and publication of offsets.
- Each mutation persists one record. A 32-byte salt from a CSPRNG feeds HKDF-SHA-256 to derive the per-record key. The prefix and payload use distinct nonces under that key. The prefix authenticates the absolute offset. The payload authenticates the encrypted prefix.
- The store rebuilds the in-memory index from the authenticated log. A corrupt complete record prevents the store from opening. An incomplete tail leaves earlier records readable, is reported by verification, and requires compaction before further writes.
- Compaction and rotation use the same codec, prepare the new index before replacing the file, and abort the rewrite if an active record is unreadable. The store recognizes Bouncy Castle AES-GCM as a compatible AES-GCM implementation.

## Files and checks

- Core Storage. EncryptedEntryStore.cs, the new EncryptedRecordCodec.cs, IAppendOnlyStoreProvider.cs, the file and memory backends, and VerifyResult.cs.
- Documentation and integration. README.md, the Bouncy Castle provider comment, EncryptedStoreTests.cs, and VerifyAsyncTests.cs.
- Added or updated regressions. A read followed by concurrent puts and reopening the file, actual key–nonce pairs, an incomplete tail, corrupt tags, and compaction aborting on unreadable data.
- Static checks. Roslyn parsed the modified C# sources using C# 13 rules. `git diff --check` passed. Restore, build, and tests were skipped at the user's explicit request.

Next step. Once authorized, run restore, build, and the MSTest suite for .NET 9 and .NET 10. Opening performance with large logs and file replacement behavior on supported platforms still need runtime verification.
