# NuGet preparation

- Objective and status. Completed steps 1 and 2 of release preparation.
- Packaging. The add-on project declares Hoddmir.BouncyCastle as its PackageId and includes README.md, LICENSE, and hoddmir_128.png at the package root. Updated the title and description. Preserved the dependency updates already present in the workspace.
- Documentation. The Unreleased changelog describes format 0x01, breaking changes, and explicit provider selection. The README documents rollback, corruption, memory, and deletion. Its examples match the namespaces and the file backend lifecycle.
- Affected files. Hoddmir.Core.BouncyCastle.csproj, README.md, and CHANGELOG.md.
- Checks. Parsed the XML, resolved the three assets, checked the Core reference and the updated dependencies, verified the C# calls in the README with Roslyn, and ran `git diff --check`. The user reported that the test suite had passed before these changes.
- Next step. In step 3, generate both packages, verify their manifests and assets, and try installing them in clean projects. Packaging, build, and tests were not run during this task.
