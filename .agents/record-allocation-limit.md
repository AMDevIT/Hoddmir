# Record allocation limit

- Objective and status. Bound memory allocated from a record prefix, including an authenticated prefix in a vault supplied by an untrusted producer.
- Decisions. Limit the combined UTF-8 ID and value to 16 MiB on both encode and decode. The reader enforces the limit after prefix authentication and before allocating the body buffer. The existing padding allowance and format version 0x01 remain in use.
- Affected files. EncryptedRecordCodec.cs, EncryptedStoreTests.cs, README.md, and CHANGELOG.md.
- Checks. Restore and build succeeded. All 167 MSTest cases passed on each of .NET 9 and .NET 10. The regressions cover an authenticated oversized prefix, a rejected oversized write with no append, and a successful write and reopen at the exact limit. Git diff whitespace check passed.
- Open issues. Vaults with previously written records above the limit are rejected. This limit bounds per-record allocation. Total vault size and scan time remain proportional to the supplied data.
