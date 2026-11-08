# MAC and header verification fixes

- Objective and status. Implemented the two priority fixes identified in the review of the new log.
- MAC. AesCtrHmacSha256Provider authenticates two LE64 lengths before the AAD, nonce, and ciphertext. The store format remains 0x01. AES-CTR + HMAC test data authenticated with the previous tag must be regenerated. The regression case keeps the concatenated bytes identical while shifting the field boundaries.
- Header. The store retains the encrypted header authenticated on open or generated during creation and rotation. VerifyAsync distinguishes a modified header from an incomplete one. Compaction and rotation check the header before preparing the replacement file.
- Affected files. AesCtrHmacSha256Provider.cs, EncryptedEntryStore.cs, VerifyResult.cs, KnownAnswerTests.cs, VerifyAsyncTests.cs, and README.md.
- Checks. C# 13 syntax analysis and `git diff --check` passed. Confirmed that the .NET 9 reference assemblies expose the IncrementalHash APIs. Recomputed the test vector tag with Python's hmac module and compared it with the previous tag. Restore, build, and MSTest were skipped at the user's request.
- Open issues. Runtime validation is pending authorization. Detecting rollback to a valid copy requires a trusted external reference. Recovery from historical corruption remains a separate project.
