# Vault security tests

- Objective and status. Added the VaultSecurity MSTest category for the current format. The file-backed tests use synthetic, temporary vaults and real AES-GCM and Argon2id.
- Decisions. Measure record boundaries from the writer. Test corruption and trusted-checkpoint recovery separately. Exercise configured resource limits with valid authenticated input, and inject a rewrite failure after staging and before publication. Extend key and nonce tracking through password and key rotation.
- Affected files. FileVaultSecurityTests.cs and EncryptedStoreTests.cs.
- Checks. Reviewed the test sources and ran the Git whitespace checks. Restore, build, and MSTest were not run pending explicit authorization.
- Open issues. Runtime confirmation on .NET 9 and .NET 10. Writer exclusion uses independent file handles in one test process. Abrupt power loss and live process exposure require separate integration checks.
