# GitHub vault security check

- Objective and status. Checked the current GitHub default branch and the current task branch in isolated local copies. Verified both commit IDs over HTTPS before exporting the tracked files.
- Scope. Used synthetic vaults on Windows. Ran restore, solution build, the repository test command, a NuGet advisory query including transitive dependencies, and a separate synthetic vault probe. The tests and probes targeted .NET 9 and .NET 10.
- Affected files. Repository context notes. The audited source snapshots came from Git archives.
- Reporting. The user requested a binary answer.
- Open issues. The check covered the two verified revisions on Windows.
