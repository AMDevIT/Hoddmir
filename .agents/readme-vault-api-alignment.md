# README alignment with the vault API

- Objective and status. Updated the README to match the current format 0x01 API and the security test additions.
- Decisions. Document explicit creation and opening, independent resource limits, trusted checkpoints, verification and recovery, and the expected-offset append contract for custom backends. Add the repository-root command for the VaultSecurity category.
- Affected files. README.md and the documentation context notes.
- Checks. Roslyn parsed all 10 C# snippets and checked argument alignment in 54 method and constructor calls. Reviewed the examples and contracts against the source, confirmed the test filter option and category, and ran git diff --check. Restore, build, and test execution were outside this documentation update.
- Open issues. Runtime confirmation of the new VaultSecurity tests remains pending authorization.
