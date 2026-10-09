# FakeInterviewGuard project instructions

## Scope and identity

FakeInterviewGuard is the VS Code workspace-inspection extension in `rodhayl/VSCodeAntivir`. Its extension ID is `fakeinterviewguard.fake-interview-guard`; retain existing `fig.*` command/configuration identifiers. It is not an antivirus, sandbox or universal pre-execution interceptor.

## Working agreements

- Use ultra-high reasoning for implementation/review. Read complete affected modules and callers before editing.
- Preserve unrelated work. Make focused, reversible changes and test normal, interrupted and repeated flows.
- Strict TypeScript, CommonJS extension output, pure JavaScript runtime dependencies. Prefer the existing OpenAI-compatible client over provider-specific SDKs.
- Treat all samples as text to inspect, never code to execute. Do not run their npm scripts, hooks, tasks, workflows or network endpoints.
- Standard tests must not call a live model. Do not assume LM Studio, Ollama, any specific model, Windows or VS Code is installed/running on the current machine.
- Restricted Mode supports manual bundled-rule scans only. It must not initialize quarantine storage/model clients, load custom rules, modify files or create automatic scanning watchers.
- File changes require explicit review. Preserve changed originals, conflicts, hashes, private recovery records and backup ownership. Do not clear recovery artifacts automatically.
- Model settings are application/User scope. Preserve endpoint/input consent, cancellation, generation checks and cache invalidation.
- Remove obsolete code only after checking imports, command registrations, dynamic loads, tests and public contracts. Keep historical claims marked as historical, not as current evidence.

## Layout

`extension/src/extension.ts` registers the editor lifecycle and commands. `scanner/` runs local signatures, heuristics, package-manifest and task checks. `rules/` loads declarative rules. `interceptors/` contains historical names for read-only configuration inspection plus explicit remediation. `safety/` and `quarantine/` handle file preservation. `providers/` renders findings; `llm/` handles optional model input/output.

JSON rules live in `extension/rules/`, prompts in `extension/prompts/`, automated tests in `extension/test/`, and inspection samples in top-level `samples/`. The `ast` matcher is a legacy regex alias, not AST analysis. Unsupported `file-structure` matchers must fail loading visibly.

## Verification

Run from `extension/`: `npm ci --ignore-scripts`, `npm run typecheck`, `npm run lint`, `npm test`, `npm run benchmark`, `npm run package`, `npm run verify:package`. Node 22.13+ is required. Real integration uses `@vscode/test-electron`; headless Linux needs a supported display/Xvfb environment. Do not bypass OS/security restrictions to launch it.

The unit runner must execute its tests and propagate failures. Read fixtures, never execute them. Benchmark results are author-built characterization with explicit false positives, corpus identity and timing scope. They do not establish detection effectiveness.

Follow `docs/VERIFICATION.md` for exact package identity and installed-editor acceptance. A blocked native check stays blocked; compilation or mocked tests cannot replace it. `scripts/prepare-package.js` generates packaged documents/metadata from canonical sources. Do not commit generated documents, VSIX files, out/, node_modules/, logs or caches. Use `docs/RECOVERY.md` for interrupted operations.
