# Store verification in the console app

- Objective and status. Added a full file-backed test cycle to the existing console app using project references.
- Decisions. The console runs the cycle before the existing data generators. The cycle uses a dedicated temporary file that is removed at the end and Argon2id parameters chosen for fast test execution.
- Coverage. Creation, writing after a read, overwriting, closing, reopening with Bouncy Castle AES-GCM, deletion, log verification, compaction, and rotation with a password change. The console checks that the old password is rejected and that the value remains intact when reopened with the new password. Creation uses .NET AES-GCM where supported.
- Affected files. Hoddmir.Tests.ConsoleApp/Program.cs and TestProvider.cs.
- Checks. C# 13 syntax analysis and `git diff --check`. Restore, build, and console execution were outside the authorized scope.
- Next step. Run Hoddmir.Tests.ConsoleApp to verify the workflow.

## Writes after reopening

- Extended the cycle to four sessions on the same file. The second session adds a key, overwrites a value, and deletes a key. After compaction and rotation, the third session adds another key and deletes the key added in the second session.
- The final reopen compares the bytes of the remaining values, checks that deleted keys are absent, and verifies the authenticated record count. The expected counts are 3, 6, 2, 2, and 4.
- C# 13 syntax analysis, argument alignment checks, and `git diff --check` passed. The console app was not run.
