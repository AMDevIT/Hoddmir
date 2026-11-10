# Live index allocation limits

- Objective and status. Bounded the in-memory index during appends and reconstruction from an authenticated vault. The on-disk format remains 0x01.
- Decisions. Limit the live index to 65,536 IDs and 16 MiB of combined UTF-8 ID bytes. Overwrites preserve the budget and deletes release it. Update the byte count only after a successful append and flush. Rebuilding validates every mutation before adding it to the index.
- Affected files. EncryptedEntryStore.cs, EncryptedRecordCodec.cs, EncryptedStoreTests.cs, README.md, and CHANGELOG.md.
- Checks. Restore and build succeeded on Windows. All 169 tests passed on each of .NET 9 and .NET 10. Regressions cover the exact count boundary after reopen, rejected writes leaving the log unchanged, replacement and deletion at the limits, and an authenticated imported log exceeding the aggregate ID byte limit.
- Open issues. A development vault whose history exceeds the live index limits is rejected on open. Scan time remains proportional to the log length. Filesystem behavior still needs verification on supported Unix platforms.
