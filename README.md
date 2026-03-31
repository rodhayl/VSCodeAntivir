# FakeInterviewGuard

A VS Code extension that detects malware patterns from the **Contagious Interview** campaign (DPRK/Lazarus group) and related supply-chain attacks targeting developers.

## Overview

FakeInterviewGuard scans your workspace for malicious code patterns commonly used in fake job interview attacks, where threat actors impersonate recruiters and deliver malware through code review tasks, npm packages, and VS Code workspace settings.

### Detection Engines

| Engine | Speed | Description |
|--------|-------|-------------|
| **Signature** | <10ms | JSON rule-based pattern matching (regex, string, entropy) |
| **Heuristic** | <10ms | Pattern density, code entropy, obfuscation detection |
| **npm Audit** | <50ms | Typosquatted packages, suspicious install scripts |
| **VS Code Tasks** | <10ms | Malicious `tasks.json` with shell commands |
| **LLM Analysis** | ~5-30s | AI-powered deep analysis via local or cloud LLMs |

### Detected Malware Families

- **BeaverTail** — Credential stealer disguised as npm packages
- **OtterCookie** — Multi-stage backdoor with reverse shell capabilities
- **InvisibleFerret** — Data exfiltration trojan
- **General** — Obfuscated code, encoded payloads, reverse shells

## Features

- 🔍 **Real-time scanning** on file open/save with inline diagnostics
- 🤖 **LLM-powered deep analysis** via LM Studio, Ollama, or any OpenAI-compatible API
- 📋 **9 built-in detection rules** covering the Contagious Interview kill chain
- 🛡️ **Quick fixes & code actions** with remediation guidance
- 📊 **Security dashboard** with threat overview (webview panel)
- 🌳 **Threat tree view** in the sidebar
- 🔧 **Extensible** — add new JSON rules or LLM prompt templates without code changes

## Quick Start

### Install from VSIX

```bash
cd extension
npm install
npm run compile
npx vsce package --no-dependencies --allow-missing-repository
code --install-extension fake-interview-guard-0.1.0.vsix
```

### Commands

| Command | Description |
|---------|-------------|
| `FIG: Scan Current File` | Scan the active file for threats |
| `FIG: Scan Workspace` | Scan all workspace files |
| `FIG: Show Dashboard` | Open the security dashboard panel |
| `FIG: Reload Rules` | Reload detection rules from disk |
| `FIG: LLM Analyze File` | Run LLM deep analysis on current file |
| `FIG: LLM Explain Threat` | Get AI explanation of a selected threat |
| `FIG: LLM Suggest Rule` | Ask LLM to generate a detection rule |
| `FIG: LLM Status` | Check LLM provider connection status |

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
  "matchers": [
    { "id": "m1", "type": "regex", "pattern": "suspicious\\.pattern\\(" }
  ],
  "condition": { "type": "all", "of": ["m1"] },
  "appliesTo": { "filePatterns": ["**/*.js", "**/*.ts"] }
}
```

Matcher types: `string`, `string-any`, `regex`, `entropy`

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

The `samples/` directory contains **safe, simulated** malware files that mimic real Contagious Interview attack patterns for testing purposes:

```
samples/
├── stage0-social-engineering/    # Fake recruiter messages
├── stage1-initial-access/        # Malicious tasks.json, npm packages
├── stage2-backdoors/             # OtterCookie, BeaverTail simulations
├── stage3-data-collection/       # Data exfiltration patterns
└── stage4-persistence/           # Scheduled task persistence
```

> ⚠️ These files contain **no actual malicious payloads** — they use safe patterns that trigger the detection rules.

## Development

```bash
cd extension
npm install
npm run compile        # TypeScript → out/
npm test               # Run VS Code integration tests
npx vsce package --no-dependencies --allow-missing-repository
```

### Project Structure

```
extension/
├── src/
│   ├── extension.ts              # Entry point, command registration
│   ├── scanner/                  # Core scanning pipeline
│   │   ├── models/               # Severity, Threat, Rule, ScanResult
│   │   ├── analyzers/            # Entropy, string, URL, typosquat
│   │   └── engines/              # Signature, heuristic, npm-audit, vscode-task, llm
│   ├── rules/                    # Rule loader
│   ├── providers/                # VS Code UI providers
│   └── llm/                      # LLM client, cache, prompts, parser
├── rules/                        # JSON detection rules
├── prompts/                      # LLM prompt templates
└── test/                         # Integration tests
```

## License

This project is for educational and research purposes.

## References

- [Microsoft Security Blog: Contagious Interview](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)
- [MITRE ATT&CK: Lazarus Group](https://attack.mitre.org/groups/G0032/)
