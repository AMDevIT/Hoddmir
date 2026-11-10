# Unused variable cleanup

- Objective and status. Reviewed all repository C# source files for unread local variables, exception variables and out-variable declarations. Removed two additional names that existed only to hold asynchronously disposed resources.
- Decisions. Use await-using expressions for the unexpected successful vault open in the console lifecycle and the independent file-open helper in the security tests. Preserve opening, exception propagation, disposal and writer-lock lifetime. Keep public AlgorithmId fields, which are API members rather than unused locals.
- Existing fixes. The previous code-scanning changes already removed the unused final DoFinal result assignments in both Bouncy Castle providers and made the ChaCha20 test assert its expected ciphertext and tag (alerts 7, 8, 10 and 12). Preserve these changes.
- Affected files. TestProvider.cs, FileVaultSecurityTests.cs, this note and context.md.
- Checks. Read-only Roslyn syntax inspection and manual review of the findings and changes. No compilation, restore, build, tests or CodeQL execution, as explicitly requested by the user. Git whitespace checks passed.
- Open issues and next step. The source review found no further unread local declarations. This syntax-level review does not replace compiler or analyzer diagnostics. The user will run the build and CodeQL to confirm the warning list.
