# AGENTS.md — FakeInterviewGuard Project Preferences & Agent Instructions

## Project Overview
FakeInterviewGuard is a VS Code extension that detects malware patterns from the
"Contagious Interview" (DPRK/Lazarus) campaign and related supply-chain attacks.
It uses a multi-engine scanning pipeline: JSON-based signature rules, heuristic
analysis, npm audit, VS Code task analysis, and (planned) LLM-powered deep analysis.

## User Preferences

### Development Philosophy
- **Effort & reasoning**: Always set to ultra-high. Think deeply before acting.
- **Test-driven**: Every feature must have passing tests (unit + integration).
  Verify in VS Code directly — don't just trust compilation.
- **Incremental delivery**: Build → test → verify → iterate. Never ship untested code.
- **Short POC for slow operations**: LLM inference is slow (~20-30s per call on
  local 4B models). POC tests should use small snippets and minimal round-trips.

### Technology Choices
- **Universal libraries over provider-specific ones**: Prefer a single library
  that supports LM Studio, Ollama, Unsloth Studio, and cloud providers seamlessly.
  The `openai` npm package (with `baseURL` override) is the agreed universal
  connector — all local providers expose OpenAI-compatible APIs.
- **JSON-based extensibility**: Detection rules, prompt templates, and LLM analysis
  profiles should all be JSON/Markdown files that anyone can add without modifying
  TypeScript code.
- **No native dependencies**: The extension must be a pure-JS VSIX that works
  cross-platform (Windows, macOS, Linux) without compilation steps.
- **CommonJS output**: VS Code extensions require CJS modules as of 2026.

### Code Style
- Minimal comments — only when something needs clarification.
- TypeScript strict mode.
- Surgical changes — don't modify unrelated code.
- Clean up temp files after tasks.

### Testing Preferences
- Use `@vscode/test-electron` for integration tests inside VS Code.
- Use plain Node.js `require()` for unit tests of scanner core (no VS Code needed).
- Always test with the actual fake samples in `samples/`.
- For LLM tests: use `qwen3.5-4b` on LM Studio (localhost:1234) — it's installed
  and running. Keep LLM test prompts short (< 500 tokens input).

### Environment
- **OS**: Windows 11
- **IDE**: VS Code (installed, used for direct testing)
- **LM Studio**: Running on `http://localhost:1234` with models:
  - `qwen3.5-4b` (primary test model)
  - `qwen/qwen3.5-9b` (available, larger)
  - `text-embedding-qwen3-embedding-0.6b` (embeddings)
  - `text-embedding-nomic-embed-text-v1.5` (embeddings)
- **Ollama**: Not currently running (may be installed later)
- **Node.js**: Available, npm for package management

## Architecture Decisions (Established)

### Extension Structure
```
extension/
├── src/
│   ├── extension.ts          # Main entry point
│   ├── scanner/              # Core scanning pipeline
│   │   ├── models/           # Severity, Threat, Rule, ScanResult interfaces
│   │   ├── analyzers/        # Entropy, string, URL, typosquat analyzers
│   │   └── engines/          # Signature, heuristic, npm-audit, vscode-task
│   ├── rules/                # Rule loader + rule engine
│   ├── providers/            # VS Code UI: diagnostics, code actions, tree, dashboard
│   └── llm/                  # LLM client, cache, prompts, parser
├── rules/                    # JSON detection rule files
│   ├── contagious-interview/ # Campaign-specific rules (7 files)
│   └── general/              # General security rules (2 files)
├── prompts/                  # LLM prompt templates (.prompt.md)
│   ├── default/              # General analysis prompts (3 files)
│   └── contagious-interview/ # Campaign-specific prompts (1 file)
└── test/                     # Integration tests
```

### Scanner Pipeline
```
File Content → Signature Engine (JSON rules, <10ms)
            → Heuristic Engine (pattern density, entropy)
            → npm Audit Engine (package.json analysis)
            → VS Code Task Engine (tasks.json analysis)
            → LLM Analysis Engine (async, on-demand, ~5-30s)
```

### LLM Integration (Implemented)
- **Library**: `openai` npm package — universal connector via OpenAI-compatible API
- **Provider support**: LM Studio, Ollama, Unsloth Studio, cloud OpenAI, Azure,
  any endpoint that speaks `/v1/chat/completions`
- **Mode**: Async, on-demand (NOT real-time — too slow for on-save scanning)
- **Output**: Structured JSON parsed into Threat objects
- **Caching**: Content-hash-based (SHA-256) to avoid re-analyzing identical code
- **Commands**: `fig.llmAnalyze`, `fig.llmExplain`, `fig.llmSuggestRule`, `fig.llmStatus`
- **Prompt templates**: `.prompt.md` files with YAML frontmatter + Markdown body

## Adding New Detection Patterns

### JSON Rules (fast, rule-based)
Add a `.json` file to `extension/rules/<category>/` following the schema:
```json
{
  "id": "unique-id",
  "name": "Human Name",
  "severity": "critical|high|medium|low|info",
  "matchers": [
    { "id": "m1", "type": "string|regex|string-any|entropy", "pattern": "..." }
  ],
  "condition": { "type": "all|any|threshold", "of": ["m1"], "minimum": 1 },
  "appliesTo": { "filePatterns": ["**/*.js"] }
}
```

### LLM Prompt Templates (deep analysis)
Add a `.prompt.md` file to `extension/prompts/<category>/` with YAML frontmatter
and markdown body.

## Key Contacts
- Publisher: fakeinterviewguard
- Extension ID: fakeinterviewguard.fake-interview-guard
