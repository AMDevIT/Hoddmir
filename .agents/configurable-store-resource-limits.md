# Configurable store resource limits

- Objective and status. Added StoreBuilder.WithResourceLimits for the active ID count, aggregate UTF-8 ID bytes, and record content bytes. The existing defaults and on-disk format 0x01 are preserved.
- Decisions. The builder validates limits before opening and snapshots them for the store instance. The vault does not carry this policy. Encoding and decoding use the same record limit. The store checks index capacity before record allocation and before inserting each authenticated record during index reconstruction.
- Affected files. EncryptedEntryStore.cs, EncryptedRecordCodec.cs, EncryptedStoreTests.cs, README.md, and CHANGELOG.md.
- Checks. Restore and build succeeded on Windows. All 171 MSTest cases passed on each of .NET 9 and .NET 10. The tests cover raising all three limits, reopening and compacting a record above the default, and rejecting invalid limits. Checked README argument alignment and ran git diff --check.
- Open issues. A larger record content limit can increase peak memory beyond the configured byte count. Supply limits that accommodate the authenticated history when reopening a vault. Streaming is the next design topic.
