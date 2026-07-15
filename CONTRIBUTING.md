# Contributing to FakeInterviewGuard

Thank you for your interest in contributing! FakeInterviewGuard is a security tool, and we take code quality and accuracy seriously.

## Development Setup

```bash
git clone https://github.com/rulf-ra/VSCodeAntivir.git
cd VSCodeAntivir/extension
npm install
npm run compile
```

### VS Code Debug

Open the `extension/` folder in VS Code and press `F5`. This launches an Extension Development Host window with FakeInterviewGuard loaded.

```
Tasks -> Run Task -> npm: watch    # Auto-rebuild on changes
```

## Project Conventions

### Code Style
- TypeScript strict mode — no `any` without justification
- CommonJS output for VS Code compatibility
- Minimal comments — only when something non-obvious needs clarification
- Surgical changes — modify only what's needed for the feature/fix
- 2-space indentation, LF line endings

### Testing (Mandatory)
- Every feature must have passing tests
- Unit tests: plain Node.js (no VS Code required) — test scanner core, analyzers, LLM components
- Integration tests: `@vscode/test-electron` — test extension activation, commands, diagnostics
- Always test with the actual fake samples in `samples/`
- LLM tests: use small snippets, keep prompts <500 tokens input

### Adding Detection Rules

1. Create a `.json` file in `extension/rules/<category>/`
2. Follow the rule schema:
   ```json
   {
     "id": "unique-rule-id",
     "name": "Human Readable Name",
     "version": "1.0.0",
     "severity": "critical|high|medium|low|info",
     "confidence": "high|medium|low",
     "description": "What this rule detects",
     "category": "campaign-category",
     "mitre": {
       "tactic": "MITRE Tactic Name",
       "technique": "T####.##",
       "name": "MITRE Technique Name"
     },
     "appliesTo": {
       "languages": ["javascript"],
       "filePatterns": ["**/*.js"]
     },
     "matchers": [
       { "id": "m1", "type": "regex", "pattern": "your\\.regex\\.here" }
     ],
     "condition": { "type": "any", "of": ["m1"] },
     "remediation": {
       "message": "How to fix it",
       "actions": ["neutralize", "quarantine"]
     }
   }
   ```
3. Matcher types: `string`, `string-any`, `regex`, `entropy`, `ast`, `file-structure`
4. Test with a sample file that should trigger the rule
5. Test with a clean file that should NOT trigger the rule

### Adding LLM Prompt Templates

Create a `.prompt.md` file in `extension/prompts/<category>/`:

```markdown
---
name: Template Name
max_tokens: 1024
temperature: 0.1
---

## System
Your system prompt here. Specify JSON output format.

## User
Your user prompt here. Use {{code}}, {{filename}}, {{language}} variables.
```

### Commit Guidelines
- Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`
- Scope when applicable: `feat(scanner): add new heuristic for...`
- No force pushes to main
- No secret commits — verify `.gitignore` before committing

## Development Workflow

1. Fork and create a feature branch from `main`
2. Implement the feature with accompanying tests
3. Run `npm run compile` and `npm test` — everything must pass
4. Run `npm run lint` — no ESLint errors
5. Squash related commits and push
6. Open a pull request with the template

## Architecture Overview

```
File Content → Signature Engine → Heuristic Engine → npm Audit Engine
              → VS Code Task Engine → LLM Analysis Engine (async)
```

Key modules:
- `scanner/` — core pipeline and engines
- `rules/` — rule loader and execution engine
- `analyzers/` — entropy, string, URL, typosquat analyzers
- `providers/` — VS Code UI (diagnostics, tree, dashboard, status bar)
- `llm/` — client, cache, prompt builder, response parser
- `interceptors/` — task, npm, git config security interceptors
- `quarantine/` — file isolation, restore, manifest management

## Code of Conduct

This project follows the spirit of the VS Code Community Code of Conduct:
- Be respectful and constructive
- Assume good faith
- Prioritize what is best for the community
- No harassment, trolling, or discriminatory behavior

## Reporting Security Issues

If you discover a security vulnerability, especially false negatives (undetectable malware patterns), please follow the [SECURITY.md](SECURITY.md) guidelines. Do NOT open a public issue for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.