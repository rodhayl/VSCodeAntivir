# FakeInterviewGuard

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](extension/package.json)
[![VS Code](https://img.shields.io/badge/VS%20Code-%5E1.125.0-blue.svg)](https://code.visualstudio.com)
[![TypeScript](https://img.shields.io/badge/built%20with-TypeScript-3178C6.svg?logo=typescript)](https://www.typescriptlang.org)
[![Detection Rules](https://img.shields.io/badge/rules-53-orange.svg)](extension/rules)
[![LLM Powered](https://img.shields.io/badge/LLM%20Powered-qwen3.5--4b-9CF.svg)](https://lmstudio.ai)

A VS Code extension that detects malware patterns from the **Contagious Interview** campaign (DPRK/Lazarus group), **BlueNoroff** supply-chain attacks, **TeamPCP** typosquatting campaigns, and other advanced persistent threats targeting developers.

## Overview

FakeInterviewGuard scans your workspace for malicious code patterns commonly used in fake job interview attacks, where threat actors impersonate recruiters and deliver malware through code review tasks, npm packages, and VS Code workspace settings.

### Detection Engines

| Engine | Speed | Description |
|--------|-------|-------------|
| **Signature** | <10ms | JSON rule-based pattern matching (regex, string, entropy) |
| **Heuristic** | <10ms | Pattern density, code entropy, obfuscation detection |
| **npm Audit** | <50ms | Typosquatted packages, suspicious install scripts, and current known-bad packages |
| **VS Code Tasks** | <10ms | Malicious `tasks.json` with shell commands, auto-execute blocks, and hidden extension installs |
| **LLM Analysis** | ~5-30s | AI-powered deep analysis via local or cloud LLMs |

### Detection Coverage

| Category | Rules | Threats Detected |
|----------|-------|------------------|
| **Contagious Interview** | 13 | BeaverTail, OtterCookie, InvisibleFerret, WASM loaders, credential harvesters |
| **Supply Chain** | 5 | Dependency confusion, lockfile injection, manifest poisoning, postinstall hacks |
| **Credential Harvesting** | 4 | SSH keys, cloud credentials, crypto wallets, browser profiles |
| **Persistence** | 4 | Schtask, registry, launchd, cron persistence mechanisms |
| **GitHub Actions** | 5 | Workflow injection, self-hosted runner abuse, secret exfiltration |
| **BlueNoroff** | 3 | MACWebT RAT, cross-platform dropper, axios compromise |
| **TeamPCP** | 5 | Trivy IOC, steganography, cloud stealers, CanisterWorm |
| **Silver Fox** | 2 | AtlasCross RAT, typosquatted domains |
| **Russian APT** | 2 | RoadK1ll implant, CTRL toolkit |
| **General** | 4 | Eval obfuscation, suspicious network, git hooks, git config exploits |
| **IDE Extensions** | 2 | Secondary VSIX installers, workspace exfiltration loaders |
| **AI Tooling** | 2 | API key theft, source-code exfiltration plugins |
| **Stealth** | 2 | Blockchain dead-drops, hidden Unicode obfuscation |
| **Total** | **53** | **13 rule categories covering modern developer-targeting campaigns** |

### Detected Malware Families

- **BeaverTail** — Credential stealer disguised as npm packages
- **OtterCookie** — Multi-stage backdoor with reverse shell capabilities
- **InvisibleFerret** — Data exfiltration trojan
- **MACWebT** — macOS RAT from BlueNoroff campaign
- **AtlasCross** — RAT from Silver Fox campaign
- **RoadK1ll** — APT implant from Russian threat actors
- **CanisterWorm** — Self-propagating malware from TeamPCP

## Features

- 🔍 **Real-time scanning** on file open/save with inline diagnostics
- 🤖 **LLM-powered deep analysis** via LM Studio, Ollama, or any OpenAI-compatible API
- 📋 **53 detection rules** covering modern developer-targeting campaigns, IDE abuse, and stealth tradecraft
- 🛡️ **Security interceptors** for tasks.json, npm scripts, and git config (block before execution)
- 📦 **Quarantine manager** with restore capability and SHA-256 verification
- 📊 **Security dashboard** with threat overview (webview panel)
- 🌳 **Threat tree view** in the sidebar with severity-based filtering
- 🔧 **Extensible** — add new JSON rules or LLM prompt templates without code changes
- 🎯 **MITRE ATT&CK mapped** — all rules linked to ATT&CK techniques for attack-graph traceability

## Quick Start

### Install from VSIX

```bash
cd extension
npm install
npm run compile
npx vsce package
code --install-extension fake-interview-guard-1.0.0.vsix
```

### Commands

| Command | Description |
|---------|-------------|
| `FIG: Scan Current File` | Scan the active file for threats |
| `FIG: Scan Workspace` | Scan all workspace files |
| `FIG: Show Dashboard` | Open the security dashboard panel |
| `FIG: Show Quarantine` | Open quarantine manager |
| `FIG: Quarantine Current File` | Move flagged file to quarantine |
| `FIG: Reload Rules` | Reload detection rules from disk |
| `FIG: LLM Analyze File` | Run LLM deep analysis on current file |
| `FIG: LLM Explain Threat` | Get AI explanation of a selected threat |
| `FIG: LLM Suggest Rule` | Ask LLM to generate a detection rule |
| `FIG: LLM Status` | Check LLM provider connection status |

## Architecture

````mermaid
graph TD
    subgraph "File Input"
        A["Source File (.js/.ts/.py/.json/.ps1/.sh/.yml/.yaml/.go/.mod)"]
    end

    subgraph "Scanning Pipeline"
        B["Signature Engine<br>JSON rules, regex/string match"]
        C["Heuristic Engine<br>entropy, obfuscation, eval density"]
        D["npm Audit Engine<br>known-bad packages, typosquat, scripts"]
        E["VS Code Task Engine<br>auto-execute, shell commands, piped exec"]
        F["LLM Analysis Engine<br>AI deep analysis, async, cached"]
    end

    subgraph "Security Interceptors"
        G["Task Interceptor<br>blocks malicious tasks.json"]
        H["npm Script Interceptor<br>blocks dangerous lifecycle scripts"]
        I["Git Config Interceptor<br>blocks core.fsmonitor exploits"]
    end

    subgraph "Output"
        J["Diagnostics Provider<br>inline warnings/errors"]
        K["Threat Tree View<br>sidebar explorer"]
        L["Dashboard Panel<br>webview statistics"]
        M["Quarantine Manager<br>file isolation + restore"]
        N["Blocking Notifications<br>modal alerts on critical threats"]
    end

    A --> B --> C --> D --> E --> F
    G --> J
    H --> J
    I --> J
    B --> J
    C --> J
    D --> J
    E --> J
    F --> J
    J --> K
    J --> L
    J --> M
    G --> N
    H --> N
    I --> N
````

### Project Structure

```
extension/
├── src/
│   ├── extension.ts              # Entry point, command registration
│   ├── scanner/                  # Core scanning pipeline
│   │   ├── models/               # Severity, Threat, Rule, ScanResult
│   │   ├── analyzers/            # Entropy, string, URL, typosquat
│   │   └── engines/              # Signature, heuristic, npm-audit, vscode-task, llm
│   ├── rules/                    # Rule loader + rule engine
│   ├── providers/                # VS Code UI: diagnostics, code actions, tree, dashboard
│   ├── llm/                      # LLM client, cache, prompts, parser
│   ├── interceptors/             # Task, npm, git config interceptors
│   ├── quarantine/               # Quarantine manager, tree, panel
│   └── notifications/            # Blocking notification service
├── rules/                        # JSON detection rules (53 files)
│   ├── contagious-interview/     # 13 rules
│   ├── ai-tooling/               # 2 rules
│   ├── ide-extensions/           # 2 rules
│   ├── stealth/                  # 2 rules
│   ├── general/                  # 4 rules
│   ├── supply-chain/             # 5 rules
│   ├── credential-harvesting/    # 4 rules
│   ├── persistence/              # 4 rules
│   ├── github-actions/           # 5 rules
│   ├── bluenoroff/               # 3 rules
│   ├── teampcp/                  # 5 rules
│   ├── silver-fox/               # 2 rules
│   └── russian-apt/              # 2 rules
├── prompts/                      # LLM prompt templates
│   ├── default/                  # General analysis prompts (3)
│   └── contagious-interview/     # Campaign-specific prompts (1)
└── test/                         # Unit + integration tests
```

### MITRE ATT&CK Mapping

All 53 detection rules are mapped to MITRE ATT&CK techniques:

| Tactic | Techniques Covered |
|--------|-------------------|
| **Initial Access** | T1195.001 Supply Chain, T1195.002 Software Dependencies, T1566 Phishing |
| **Execution** | T1059 Command Interpreter, T1059.007 JavaScript, T1204 User Execution |
| **Persistence** | T1053 Scheduled Task, T1547 Boot Execution, T1136-create-account, T1053.005/cron |
| **Credential Access** | T1552 UNProtected Credentials, T1556 Prompt for Credentials, T1110 Brute Force |
| **Defense Evasion** | T1027 Obfuscation, T1140 Decompile, T1036 Masquerading |
| **Exfiltration** | T1041 Exfiltration Over C2, T1048 Ingress Transfer, T1005 I/O from Local |
| **Command & Control** | T1071 App Layer Protocol, T1095 Web Services, T1105 Ingress Tool Transfer |

## LLM Integration

FakeInterviewGuard integrates with local LLM providers for deep code analysis that goes beyond pattern matching.

### Supported Providers

| Provider | Default URL | Setup |
|----------|-------------|-------|
| **LM Studio** | `http://localhost:1234/v1` | Install → load a model → start server |
| **Ollama** | `http://localhost:11434/v1` | `ollama serve` → `ollama pull <model>` |
| **OpenAI** | `https://api.openai.com/v1` | Set API key in settings |
| **Custom** | Any URL | Any OpenAI-compatible endpoint |

### Configuration

```jsonc
// settings.json
{
  "fig.llm.enabled": true,
  "fig.llm.provider": "lmstudio",    // lmstudio | ollama | openai | custom
  "fig.llm.model": "qwen3.5-4b",
  "fig.llm.baseUrl": "",              // auto-detected from provider
  "fig.llm.apiKey": "",               // only needed for cloud providers
  "fig.llm.maxTokens": 1024,
  "fig.llm.temperature": 0.1,
  "fig.llm.timeout": 60000,
  "fig.llm.autoAnalyze": false,       // auto-run LLM on high-severity findings
  "fig.llm.promptProfile": "default"  // or "contagious-interview"
}
```

## Adding Detection Rules

Add a JSON file to `extension/rules/<category>/`:

```json
{
  "id": "my-custom-rule",
  "name": "My Custom Detection",
  "severity": "high",
  "description": "Detects ...",
  "mitre": {
    "tactic": "Execution",
    "technique": "T1059.007",
    "name": "JavaScript"
  },
  "matchers": [
    { "id": "m1", "type": "regex", "pattern": "suspicious\\.pattern\\(" }
  ],
  "condition": { "type": "all", "of": ["m1"] },
  "appliesTo": { "filePatterns": ["**/*.js", "**/*.ts"] }
}
```

Matcher types: `string`, `string-any`, `regex`, `entropy`, `ast`, `file-structure`

## Adding LLM Prompt Templates

Add a `.prompt.md` file to `extension/prompts/<category>/`:

```markdown
---
name: My Analysis
max_tokens: 1024
temperature: 0.1
---

## System
You are a security analyst. Analyze the code for threats.
Return JSON: {"malicious": boolean, "confidence": number, "threats": [...]}

## User
Analyze this {{language}} file ({{filename}}):
```
{{code}}
```
```

Variables: `{{code}}`, `{{filename}}`, `{{language}}`

## Fake Malware Samples

The `samples/` directory contains **safe, simulated** fixtures that mimic real developer-targeting attack patterns for testing purposes:

```
samples/
├── benign/                       # Clean control fixtures
├── malicious-deps/               # Known-bad dependency examples
├── stage1-initial-access/        # Malicious tasks, workflows, loaders, deps
├── stage2-backdoors/             # OtterCookie, dead-drops, obfuscation
└── stage3-data-collection/       # AI assistant and wallet exfiltration patterns
```

> ⚠️ These files contain **no actual malicious payloads**. They use inert patterns and localhost/demo endpoints to trigger the detection rules safely.

## Development

```bash
cd extension
npm install
npm run compile        # TypeScript → out/
npm test               # Run unit + VS Code integration tests
npm run lint           # Run ESLint
npx vsce package       # Build VSIX package
```

## License

This project is licensed under the [MIT License](LICENSE).

## References

- [Microsoft Security Blog: Contagious Interview](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)
- [MITRE ATT&CK: Lazarus Group](https://attack.mitre.org/groups/G0032/)
- [MITRE ATT&CK: BlueNoroff](https://attack.mitre.org/groups/G0130/)
- [MITRE ATT&CK: Silver Fox](https://attack.mitre.org/groups/G0065/)
