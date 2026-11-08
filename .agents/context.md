## Hoddmir feature analysis

- Objective and status. Completed the initial review and static analysis.
- Decision. Compared the source code and test cases with the README and changelog.
- Affected files. Reviewed Core, Bouncy Castle, MSTest, and the console app. Added the [analysis note](feature-analysis.md).
- Checks. Reviewed the code and the uniqueness test. Restore, build, and tests were outside the agreed scope.
- Open issues. Reproduce the append and nonce reuse defects at runtime before validating file persistence.

## Hoddmir feature recheck

- Objective and status. Completed the recheck and confirmed the findings on append, nonces, the index, and the Bouncy Castle provider.
- Decision. Distinguished the isolated FileStream check from the findings confirmed by tracing the code.
- Affected files. Added the [recheck note](feature-recheck.md) and updated this context. Reviewed the store, file backend, Bouncy Castle provider, tests, and README.
- Checks. The FileStream check wrote at position 4 with a file length of 9. Verified the nonce and index reconstruction paths. Restore, build, and MSTest were not run.
- Open issues. Integration tests and fixes. The next step is to add regression tests that observe actual nonces and a read followed by a write on the file backend.

## Persistence fixes for format 0x01

- Objective and status. Implemented the agreed fixes for append, nonces, and index reconstruction.
- Decisions. Appends return the actual offset. Each record uses an HKDF-derived key, and the store rebuilds the in-memory index from the log. Compaction recovers an incomplete tail. There is no legacy compatibility path.
- Affected files. Core Storage and providers, README, and MSTest tests. See the [persistence fixes note](format-01-persistence-fixes.md).
- Checks. Roslyn C# 13 syntax analysis and `git diff --check` passed. Restore, build, and MSTest were skipped at the user's request.
- Open issues. Validate at runtime on .NET 9 and .NET 10 when authorized, with particular attention to the file backend.

## MAC and header verification fixes

- Objective and status. Completed the two priority fixes for AES-CTR + HMAC and header integrity.
- Decisions. Authenticate the AAD and ciphertext lengths. Compare the encrypted header with the validated copy before verification and rewrites. The format version is 0x01.
- Affected files. AEAD provider, store, verification result, tests, and README. See the [MAC and header verification note](mac-and-header-verification-fixes.md).
- Checks. Checked C# 13 syntax with Roslyn, ran `git diff --check`, checked the .NET 9 reference assemblies, and recomputed the tag independently. Restore, build, and MSTest were skipped at the user's request.
- Next step. Validate at runtime when authorized. Assess the threat model for rollback and recovery from corruption separately.

## NuGet preparation

- Objective and status. Completed Bouncy Castle packaging and aligned the documentation.
- Decisions. Use the Hoddmir.BouncyCastle package ID, include assets at the package root, and record the current format 0x01 changes in the Unreleased changelog.
- Affected files. Hoddmir.Core.BouncyCastle.csproj, README.md, CHANGELOG.md, and the [NuGet preparation note](nuget-preparation.md).
- Checks. Verified XML, file paths, and C# example alignment. `git diff --check` passed.
- Next step. Generate and install both packages locally.

## Store verification in the console app

- Objective and status. Added a full test cycle to the existing console app.
- Decisions. Use project references and a temporary file for verification. Run the data generators after the test cycle.
- Affected files. Program.cs, TestProvider.cs, and the [console verification note](store-console-check.md).
- Checks. C# 13 syntax analysis and `git diff --check`. The console app was neither built nor run.
- Next step. Run the console app to verify the full cycle at runtime.

## Writes after reopening in the console app

- Objective and status. Extended the cycle to four sessions, including appends, updates, and deletions after reopening and writes after rotation.
- Decision. Check keys, values, and log counts after rewrites and on the final reopen.
- Affected files. TestProvider.cs and the [console verification note](store-console-check.md).
- Checks. C# 13 syntax analysis, argument alignment checks, and `git diff --check` passed. The console app still needs to be run.

## Security audit and format 0x01 hardening

- Objective and status. Fixed the replay and robustness issues identified in the review. The development format remains 0x01 with no compatibility layer.
- Decisions. Authenticate the log as a chain, provide trusted checkpoints, and enforce exclusive writer ownership.
- Affected files. Core storage and crypto, Bouncy Castle providers, tests, README.md, CHANGELOG.md, and the [security audit note](security-audit-format-01.md).
- Checks. Restore and build succeeded. All 164 MSTest cases passed on each of .NET 9 and .NET 10. The four-provider attack matrix passed on both targets.
- Next step. Verify filesystem behavior on supported Unix platforms and have the cryptographic design independently reviewed.
