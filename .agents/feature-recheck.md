# Hoddmir feature recheck

Completed the recheck on the checkout at HEAD 57bc0cb. Reviewed the read, write, reopen, verification, and rewrite paths. Ran an isolated FileStream check in PowerShell.

- **File append.** ReadAtAsync moves the cursor of the shared stream. AppendAsync writes at the cursor, while PutAsync and DeleteAsync use the file length as the index offset. The isolated check read DATA from DATAINDEX, leaving the cursor at 4 and the length at 9. Writing NEW produced DATANEWEX, still of length 9.
- **Index nonce.** PersistIndexAsync always uses the same IndexToken. The prefix nonce combines four bytes from the store and eight bytes from the token. Snapshots therefore reuse the nonce under the same key even within a single session.
- **Payload nonces.** The first Put uses 1 for the data and 2 for the index. Index reconstruction takes the maximum only over data records with a recognized token, so the first Put after reopening uses 2 again. CompactAsync restarts at 1 with the same key and prefix. RotateDekAsync generates a new key and prefix.
- **Separate persistence.** The record and index are written and flushed separately. If a token is absent from readable snapshots, the record is invisible on reopen. A deletion interrupted before the snapshot is written can leave the previous version active.
- **Index verification.** VerifyAsync authenticates the prefix and checks the length, but skips authentication of the index payload. Corrupting only the payload tag of the sole snapshot can leave IsHealthy true and the index empty on reopen.
- **Rewrites and providers.** CompactAsync and RotateDekAsync skip unreadable active records. The store rejects the AES-GCM (BouncyCastle) name with NotSupportedException.
- **Documentation and tests.** The README describes a different prefix nonce from the one in use. Keys are encrypted in both data records and snapshots. The uniqueness test uses synthetic numbers. CorruptedDataRecordTag modifies the record prefix. Store integration tests use the memory backend.

The isolated check confirms the cursor behavior. The other findings come from tracing the source code. Restore, build, and MSTest were not run. The recommended next step is to add integration tests for the file backend and the nonces observed by the AEAD provider, then fix append behavior and nonce handling.
