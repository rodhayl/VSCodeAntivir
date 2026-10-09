# Contributing to FakeInterviewGuard

The canonical repository is [rodhayl/VSCodeAntivir](https://github.com/rodhayl/VSCodeAntivir). Keep the `FakeInterviewGuard` display name, `fakeinterviewguard.fake-interview-guard` extension ID and `fig.*` command/configuration IDs stable.

## Build and test

```sh
git clone https://github.com/rodhayl/VSCodeAntivir.git
cd VSCodeAntivir/extension
npm ci --ignore-scripts
npm run typecheck
npm run lint
npm test
npm run benchmark
npm run package
npm run verify:package
```

Use Node 22.13+ and VS Code 1.125+. `npm test` runs offline units and an isolated real Extension Host; Linux needs a display or `xvfb-run -a npm run test:integration`. Do not disable sandbox/security controls to make a host launch succeed. Report infrastructure blocks separately. See [verification](docs/VERIFICATION.md) for installed-VSIX acceptance.

For interactive development, compile then launch VS Code with `--extensionDevelopmentPath` pointing to the absolute `extension/` directory, using a disposable profile and benign workspace. The repository does not assume a particular OS, local model or running provider.

## Contracts

- Strict TypeScript, CommonJS output, no runtime native dependencies
- Changes require focused regressions and the complete applicable checks on the final source
- Scanner text is data: never execute sample code, package scripts, tasks, hooks or suspicious commands
- Restricted Mode stays read-only; no model client, custom rules, remediation, quarantine storage or automatic scanning
- Trusted remediation checks consent, snapshots and backups; preserve originals/newer work on failure
- Standard tests use stubbed model transport. Live experiments require deliberate authorization of provider, input and possible costs
- Keep logs, generated package documents, binaries, caches and recovery artifacts out of source control
- Do not claim malware efficacy, attribution, prevention or latency from synthetic fixture success

## Detection rules

Add a JSON file to `extension/rules/<category>/` with `id`, `name`, `severity`, `matchers`, `condition` and `appliesTo`. Supported matchers are `string`, `string-any`, `regex` and `entropy`. Legacy `ast` is regex-based; `file-structure` is unsupported. The loader reports invalid rules. Never add a matcher as a silent no-op.

For each rule, include an inert positive and a legitimate negative/challenge, references for factual indicators, the evidence date and a description of uncertainty. Package declarations are not installed-package evidence. Do not add attacker family names merely to increase coverage counts. Extending the corpus requires documenting labels and retaining false positives in evaluation outputs.

## Model prompts

Prompt templates live under `extension/prompts/` and use `.prompt.md`, frontmatter (`name`, `max_tokens`, `temperature`), `## System` and `## User` sections. Supported variables include `{{code}}`, `{{filename}}` and `{{language}}`. Treat generated rules and model judgments as untrusted suggestions; they must be reviewed and tested before enabling.

## Pull requests

Use a focused branch and conventional commit message. Describe observed behavior, intended behavior, failing/passing regressions, final source identity and any blocked checks. Do not remove apparently unused code based on grep alone: inspect imports, dynamic registrations, tests, package entrypoints and compatibility. Do not force-push main or commit private data.

Report sensitive extension vulnerabilities through [SECURITY.md](SECURITY.md), not a public payload. Be respectful and constructive. Contributions use the project's MIT license.
