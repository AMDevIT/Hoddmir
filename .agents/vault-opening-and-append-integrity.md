# Vault opening and append integrity

- Objective and status. Fixed implicit vault creation during open and prevented writes after changes to the authenticated header or last committed record. The on-disk format remains 0x01.
- Decisions. OpenAsync requires an initialized vault. CreateAsync requires an empty backend. File backends open existing files by default and use FileMode.CreateNew for a new path. The store hashes the last committed record in bounded chunks before append. Both built-in backends compare the expected offset under the same lock as the append.
- Affected files. EncryptedEntryStore.cs, IAppendOnlyStoreProvider.cs, both built-in backends, the console app helper, MSTest, README.md, and CHANGELOG.md.
- Checks. Restore and build succeeded. All 165 MSTest cases passed on each of .NET 9 and .NET 10. The file-backed console lifecycle passed, including cross-provider reopen, append, compaction, and password rotation. Git diff whitespace check passed.
- Open issues. Appends validate the header and last record. VerifyAsync checks the entire log. Custom backends must provide exclusive write ownership and atomic offset checking. File locking and replacement still need verification on supported Unix platforms. A trusted external checkpoint is required to detect a complete valid rollback across reopen.
