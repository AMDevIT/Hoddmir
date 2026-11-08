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

## Vault opening and append integrity

- Objective and status. Separated opening and creation, and added append preconditions. Format 0x01 is unchanged.
- Decisions. Verify the header and last record before writing. Compare the expected offset atomically with append.
- Affected files. Core storage, both built-in backends, the console app helper, MSTest, README.md, CHANGELOG.md, and the [follow-up note](vault-opening-and-append-integrity.md).
- Checks. Restore, build, and the console file lifecycle succeeded. All 165 tests passed on each of .NET 9 and .NET 10.
- Next step. Verify filesystem behavior on supported Unix platforms.

## Record allocation limit

- Objective and status. Added a 16 MiB limit on combined UTF-8 ID and value size in format 0x01.
- Decisions. Use the same limit for reads and writes. Reject oversized authenticated prefixes before body allocation.
- Affected files. The record codec, its integration tests, README.md, CHANGELOG.md, and the [allocation limit note](record-allocation-limit.md).
- Checks. Restore and build succeeded. All 167 tests passed on each of .NET 9 and .NET 10.
- Open issues. Previously created oversized development records are rejected. Platform verification remains limited to Windows.

## Live index allocation limits

- Objective and status. Bounded the live index on writes and reopen in format 0x01.
- Decisions. Enforce a limit of 65,536 live IDs and 16 MiB of combined UTF-8 ID bytes. Overwrites preserve the budget and deletes release it.
- Affected files. Core storage, integration tests, README.md, CHANGELOG.md, and the [index limit note](live-index-allocation-limits.md).
- Checks. Restore and build succeeded. All 169 tests passed on each of .NET 9 and .NET 10.
- Open issues. Vaults whose authenticated history exceeds the limits are rejected on reopen. Runtime verification covered Windows.

## Configurable store resource limits

- Objective and status. Added WithResourceLimits for active IDs, aggregate UTF-8 ID bytes, and record content bytes.
- Decisions. Preserve the existing defaults and format 0x01. Apply caller-supplied limits consistently during writes, opening, and rewrites.
- Affected files. Core storage, integration tests, README.md, CHANGELOG.md, and the [resource limits note](configurable-store-resource-limits.md).
- Checks. Restore and build succeeded. All 171 tests passed on each of .NET 9 and .NET 10.
- Next step. Design authenticated streaming for large files.

## Vault security tests

- Objective and status. Added MSTest coverage for vault tampering, rollback, incomplete tails, resource limits, rewrite errors, and writer exclusion. Extended provider tests through key and password rotation.
- Decisions. Use temporary vaults and checkpoints captured independently of later mutations.
- Affected files. FileVaultSecurityTests.cs, EncryptedStoreTests.cs, and the [security test note](vault-security-tests.md).
- Checks. Source review and Git whitespace checks. Restore, build, and MSTest are pending explicit authorization.
- Next step. Run the VaultSecurity category on .NET 9 and .NET 10 when authorized.

## Vault write failure tests

- Objective and status. Added file-backed MSTest coverage for a partial append and for a surviving complete append after a reported flush error.
- Decisions. Inject the errors through a test-only wrapper and check that the faulted session cannot append or issue a checkpoint.
- Affected files. FileVaultSecurityTests.cs and the [write failure test note](vault-write-failure-tests.md).
- Checks. Source review and Git whitespace check. The user will run the tests.
- Next step. Run the VaultSecurity category on .NET 9 and .NET 10.

## README alignment with the vault API

- Objective and status. Updated README usage and reference sections for format 0x01.
- Decisions. Explain configurable limits, checkpoint storage and reopen, verification and recovery, the custom backend contract, and the security test command.
- Affected files. README.md and the [documentation note](readme-vault-api-alignment.md).
- Checks. Verified source signatures and test category, parsed all C# examples with Roslyn, checked multiline argument alignment, and ran git diff --check. Restore, build, and tests were outside this documentation update.
- Next step. Run the VaultSecurity test category when authorized.
