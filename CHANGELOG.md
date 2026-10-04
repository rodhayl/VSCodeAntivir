# Changelog

All notable changes to FakeInterviewGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Safety and correctness
- Make startup configuration inspection read-only and require explicit review before remediation; preserve verified backups and refuse changed, dirty or symlink targets.
- Make quarantine conflict-safe, private and recoverable across metadata failures and independent windows; refuse corrupt/escaping entries, snapshot destructive selections and confirm actions in the extension host.
- Preserve multi-root findings; apply file exclusions, size limits and minimum severity consistently; report incomplete scans, scan unopened selected files and clear deleted-file findings.
- Scope LLM configuration to User settings, add endpoint/input consent, abort cancelled requests and reject stale results. Keep real-provider experiments outside the default test runner.
- Execute the actual unit suite from its CLI entrypoint, with benign regression coverage for these boundaries.

## [1.0.0] - 2026-05-01

### Added
- 50 detection rules across 12 threat actor campaign categories
- Signature, heuristic, npm audit, VS Code task, and LLM analysis engines
- LLM integration via OpenAI-compatible API (LM Studio, Ollama, OpenAI, custom)
- SHA-256 content-based LLM response caching
- Security interceptors for tasks.json, npm scripts, and git config (blocks before execution)
- Quarantine manager with file isolation, restore capability, and SHA-256 integrity verification
- Blocking notification service for critical threats
- Threat tree view and security dashboard webview panel
- MITRE ATT&CK technique mappings on all 50 rules
- 20 known-bad package entries in npm audit engine (BlueNoroff, TeamPCP, Silver Fox campaigns)
- Typosquatting detection for 60+ top npm packages via Levenshtein distance
- ESLint configuration with TypeScript strict mode support
- .vscodeignore for clean VSIX packaging
- Full MIT license
- README, CHANGELOG, CONTRIBUTING, SECURITY documentation
- GitHub issue and pull request templates

### Changed
- Updated extension version to 1.0.0
- Updated README with accurate rule counts, architecture diagram, badges
- Added repository, bugs, and icon fields to package.json

### Fixed
- tsconfig.json test/**/* include causing TypeScript compilation issues with .js test files
- Missing LICENSE file for marketplace publication
- Missing extension icon
- Missing ESLint config (lint script was referencing non-existent file)

## [0.1.0] - 2025-12-01

### Added
- Initial extension scaffolding
- Core scanning pipeline (signature + heuristic engines)
- 9 Contagious Interview detection rules
- 2 general security detection rules
- Inline diagnostics provider
- Code actions provider
- Output channel for logging
- Basic command registration (scan, dashboard, reload)
- npm audit engine with known-bad packages
- VS Code task engine
- Integration test suite with @vscode/test-electron
- LLM integration framework (OpenAI-compatible API)
- LLM caching, prompt builder, response parser
- Quarantine manager
- Security interceptors (task, npm, git config)
- Blocking notifications for critical threats
- 4 LLM prompt templates
- 31 additional detection rules across 10 categories
- Sample malware files for testing
