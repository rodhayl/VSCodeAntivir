# FakeInterviewGuard

Static workspace review for VS Code. This is the extension developed in the public [VSCodeAntivir repository](https://github.com/rodhayl/VSCodeAntivir). Its stable extension ID is `fakeinterviewguard.fake-interview-guard`; commands use `FIG:`.

[![CI](https://github.com/rodhayl/VSCodeAntivir/actions/workflows/ci.yml/badge.svg)](https://github.com/rodhayl/VSCodeAntivir/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/rodhayl/VSCodeAntivir/blob/main/LICENSE)

FakeInterviewGuard reads source and configuration files, highlights suspicious patterns, and helps you review selected configuration changes. The engineering focus is consent, incomplete scan reporting, conflict-safe recovery and failure-path testing.

**Status: source-build review candidate.** The package version is 1.0.0; it does not prove a Marketplace release or installed-product acceptance. Check the actual commit and its CI results before using a build. No scan certifies a repository as safe. This extension is not an antivirus, sandbox, live threat-intelligence feed or general barrier before commands execute.

## Try it without running repository code

Prerequisites: Node.js 22.13+ (Node 24 is also supported by the build), npm and VS Code 1.125+.

```sh
git clone https://github.com/rodhayl/VSCodeAntivir.git
cd VSCodeAntivir/extension
npm ci --ignore-scripts
npm run lint
npm run test:unit
npm run benchmark
npm run package
npm run verify:package
```

Install the generated `fake-interview-guard-1.0.0.vsix` in a disposable VS Code profile using **Extensions: Install from VSIX…**. Generated `out/build-metadata.json` inside the package records source and dependency-lock hashes. See the [verification guide](https://github.com/rodhayl/VSCodeAntivir/blob/main/docs/VERIFICATION.md).

1. Open an unfamiliar repository in **Restricted Mode**. Do not trust it just to run this scanner.
2. Run **FIG: Scan Entire Workspace** or **FIG: Scan Current File**. Restricted Mode supports manual static scans and the dashboard using bundled rules and user-level scan settings. It does not initialize model clients, quarantine storage, automatic watchers or configuration-remediation prompts.
3. Review diagnostics and **FIG: Show Security Dashboard**. Inspect skipped files and errors in the FakeInterviewGuard output channel. “No findings” only describes reported results from the files actually scanned.
4. Remediation is optional. In a repository you have independently decided to trust, reload the window and run **FIG: Review Workspace Configuration**. Review the exact edit before choosing Disable. Dismissal changes nothing. Do not execute sample programs or install dependencies from a suspicious repository.
5. Test quarantine with a disposable benign text file. **FIG: Quarantine Current File** confirms removal; **FIG: Show Quarantine Manager** offers restore. An existing destination is never overwritten. Consult [recovery](https://github.com/rodhayl/VSCodeAntivir/blob/main/docs/RECOVERY.md) before handling a failed operation.

Restricted Mode limits extension behavior; it does not make files or other applications safe. Scanning is not guaranteed to finish before a task, terminal command, hook or package manager executes.

## What is implemented

- Four local inspection stages: JSON signatures, heuristic text patterns, package-manifest checks and VS Code task checks
- 53 bundled JSON rule files in 13 directories, inline diagnostics, severity filtering, a tree view and dashboard
- Explicit task/npm/Git configuration review with original-byte backups; quick fixes open review/details rather than deleting source lines
- Private quarantine records with SHA-256 integrity checks, exclusive restore publication and failure-path regressions
- Optional, separately invoked LLM review with endpoint/input consent, cancellation and stale-result rejection

The historical `npm-audit-engine` filename is retained for compatibility. It does **not** invoke `npm audit`, resolve lockfiles, inspect installed package contents or query a registry. Exact declarations, semver ranges and npm aliases are distinguished; a range finding means it may include a listed version, not that the version is installed. Names and campaign labels in bundled indicators are author-maintained classifications, not verified attribution or a current advisory feed.

## Evidence and limits

`npm run benchmark` reads 20 versioned synthetic text cases: 8 suspicious-pattern cases and 12 benign controls/challenges. It outputs input/source/rule hashes, per-case findings, TP/FP/TN/FN counts, per-rule positive/benign hits and p50/p95/max timings. Legitimate build scripts, startup tasks and inert comments deliberately expose false positives. This corpus is authored alongside the implementation: it is a regression and characterization tool, not an independent efficacy evaluation.

- False positives and missed behavior are possible. Literal text matches also fire inside comments and strings.
- File timings exclude startup, directory traversal, disk reads, editor UI and model calls. There is no “under 50 ms” guarantee. Workspace traversal is synchronous and can pause the Extension Host on large trees.
- Rule counts and family names are an inventory, not detection coverage. No real-malware or new-threat efficacy claim is made.
- Quarantine supports recovery, not execution isolation or tamper-proof storage. Cross-filesystem moves, symlinks, hard-linked sources and interrupted locks fail conservatively. Hostile same-user filesystem races and real power-loss durability are not universally solved.
- Mocked editor tests, Extension Host tests, packaging, installation and native GUI acceptance are separate checks. See [verification](https://github.com/rodhayl/VSCodeAntivir/blob/main/docs/VERIFICATION.md).

## Optional model analysis and privacy

LLM analysis is disabled by default. User/application settings select LM Studio, Ollama, OpenAI or a compatible custom HTTP(S) endpoint. Compatibility is protocol-level, not a guarantee for every model/deployment. Standard tests require no live provider.

Before transmission, the extension names the endpoint, model and input. Code, filename, instructions and selected finding text can leave the machine. Providers may retain input or charge for it. Analyze only code you are allowed to share; a local endpoint does not automatically imply secure handling.

Commands: **FIG: Deep Analyze with LLM**, **FIG: Explain This Threat (LLM)**, **FIG: Suggest Detection Rule (LLM)** and **FIG: Check LLM Connection**. Automatic analysis also requires session approval for the endpoint/model/workspace; settings changes revoke it. Cancellation cannot retract data already received by a provider.

Set `fig.llm.enabled`, `fig.llm.provider`, `fig.llm.model` and optionally `fig.llm.baseUrl` in User settings. Choose a model actually loaded by the provider. `fig.llm.promptProfile` is a template name such as `Security Analysis`. API keys currently use the user-level `fig.llm.apiKey` setting, not SecretStorage: avoid Settings Sync for keys and never commit them. Model output and model-reported confidence are advisory, not calibrated security evidence.

## Architecture and extension points

```text
VS Code commands/documents
  -> Scanner: size/exclusion/parse checks
  -> signatures + heuristics + local manifest checks + task checks
  -> diagnostics/tree/dashboard

Trusted review -> target/snapshot/consent checks -> FileChange or quarantine
Optional model command -> destination/input consent -> cancellable client -> stale-result checks
```

Source: `extension/src/`. Rules: `extension/rules/`. Prompt templates: `extension/prompts/`. Tests and corpus: `extension/test/`. The top-level `samples/` is inspection data; never execute its programs, tasks, workflows or package scripts.

Supported matchers are `string`, `string-any`, `regex` and `entropy`. Legacy `ast` uses predefined regular expressions, not an AST parser; it remains for compatibility and is not recommended for new rules. Unimplemented `file-structure` matchers are rejected instead of silently reporting no match. Custom rules load only in trusted sessions and can be expensive; review them first.

## Development

```sh
cd extension
npm ci --ignore-scripts
npm run typecheck
npm run lint
npm test                    # unit + real VS Code Extension Host
npm run benchmark           # synthetic text-only characterization
npm run package             # local VSIX, no publication
```

On headless Linux use `xvfb-run -a npm run test:integration` in a supported environment. Missing GUI/runtime support is a blocked check, never a passing suite. See [CONTRIBUTING](https://github.com/rodhayl/VSCodeAntivir/blob/main/CONTRIBUTING.md), [SECURITY](https://github.com/rodhayl/VSCodeAntivir/blob/main/SECURITY.md), [verification](https://github.com/rodhayl/VSCodeAntivir/blob/main/docs/VERIFICATION.md) and [recovery](https://github.com/rodhayl/VSCodeAntivir/blob/main/docs/RECOVERY.md).

Licensed under [MIT](https://github.com/rodhayl/VSCodeAntivir/blob/main/LICENSE).
