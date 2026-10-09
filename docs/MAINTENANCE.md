# Maintained surface and cleanup decisions

The extension's package entrypoint is `out/extension.js`, exporting the VS Code activation lifecycle. TypeScript imports connect scanning, model integration, reviewed remediation, quarantine and providers. `package.json` contributes stable `fig.*` commands/settings/views; those are compatibility identifiers even when historical filenames contain “interceptor” or “npm-audit”.

Other entrypoints are intentional:

- `rules/**/*.json`: recursively loaded declarative detection rules, selected by directory
- `prompts/**/*.prompt.md`: recursively loaded model templates, selected by frontmatter name
- `test/runUnit.js`: discovers every unit `*.test.js` and propagates failures
- `test/runTest.js` and `test/suite/index.js`: real isolated Extension Host tests
- `test/benchmark.js` and `test/corpus/portfolio.json`: text-only characterization
- `scripts/prepare-package.js`: generated packaged documents and content-hash provenance
- `scripts/verify-package.js`: extracted-VSIX runtime dependency/import/scanner verification, explicitly not native acceptance
- `test/live/`: deliberately excluded provider experiments; never run as part of ordinary verification
- `samples/`: referenced inspection fixtures, never executable test setup

## Removed or consolidated

Source AST import/call inventory, complete affected modules, package entrypoints and test consumers were checked before cleanup:

- `acorn` and `acorn-walk` were unused direct production dependencies. The legacy `ast` matcher was and remains regex-based. A parser pulled transitively by development tools is not a runtime feature.
- `.eslintrc.json` was superseded by ESLint 10's active `eslint.config.js`.
- `url-analyzer.ts`, `extractStringLiterals` and `defangUrl` had no runtime callers or dynamic registrations. Only direct helper tests referenced them. They were removed with those 17 helper-only assertions; scanner/rule/task URL behavior and its tests remain.
- Presentation escaping, basename handling and tactic icons now use the tested shared provider helpers. The uncalibrated security score was replaced by a finding count, and its tests now validate the actual summary contract.
- The unsupported `file-structure` no-op/interface was removed. The loader reports such custom rules as unsupported. Legacy `ast` stays supported for compatibility, explicitly documented as regex matching.
- Direct line-edit quick fixes could corrupt JSON and bypass snapshot/backup review. They now lead to explicit review or details.
- `.vscodeignore` no longer excludes production node_modules. An isolated extracted-VSIX check guards against packaging success with missing runtime dependencies.

No release history was rewritten, and all existing samples/rules/prompts remain. Old changelog wording is marked historical. Generated README/CHANGELOG copies live only in packaging output, with canonical documents at the repository root. Build output, caches, editor downloads, logs, VSIX binaries and recovery artifacts are ignored rather than committed. The generated package LICENSE copy is required distribution content, not another source of policy.

## Deliberate boundaries

The repository does not claim to solve synchronous-scan responsiveness, independent detector efficacy, threat-intelligence provenance for every legacy indicator, SecretStorage migration, hostile same-user filesystem races or universal native-platform acceptance. These are documented limits, not completed features. New features need their own scoped contracts and evidence; do not retain a placeholder API that silently does nothing.
