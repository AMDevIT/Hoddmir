# Code scanning semaphore disposal

- Objective and status. Addressed the remaining instance of CodeQL alert 25 on revision 3b7cf173533e54b07c7781cdd6881403d784f0ce. The latest message points to the semaphore field and its explicit Dispose call in the finally block.
- Decisions. After acquiring the semaphore, scope its lifetime with using. Keep Release in finally and retain await using for the writer lock. Preserve the disposal order: close vault stream, close writer lock, release semaphore, dispose semaphore. No change to the vault format or normal operation lifetime.
- Affected files. FileAppendOnlyStoreProvider.cs, this note and context.md.
- Checks. Reviewed the updated alert through the GitHub API and the local diff. Git whitespace checks passed. Restore, build, tests and CodeQL execution were not run, following the user's explicit instruction.
- Open issues and recommended next step. Rerun CodeQL after publishing this change to confirm that alert 25 closes.
