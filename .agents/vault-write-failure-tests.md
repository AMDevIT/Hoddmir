# Vault write failure tests

- Objective and status. Added two VaultSecurity MSTest cases that exercise a partial append and a flush error after a complete append.
- Decisions. Wrap the real file backend to inject each fault deterministically. Require a fresh open after either fault. Recover an incomplete tail at the saved checkpoint. Check a surviving complete record separately from trusting the updated file history.
- Affected files. FileVaultSecurityTests.cs.
- Checks. Reviewed argument alignment and ran the Git whitespace check. Restore, build, and MSTest were left for the user.
- Open issues. The simulated flush error covers the case where the complete record survives. Actual power loss and filesystem durability require separate checks.
