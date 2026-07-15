# Security Policy

## Supported Versions

| Version | Status |
|---------|--------|
| >= 1.0.0 | Actively maintained |
| < 1.0.0 | Legacy, no support |

## Reporting a Vulnerability

### False Negatives (Missing Detection)

If you discover a malware pattern or attack vector that FakeInterviewGuard should detect but currently does not:

**DO NOT open a public GitHub issue.** Instead, report via:
- GitHub Security Advisories: https://github.com/rulf-ra/VSCodeAntivir/security/advisories/new
- Include: the attack pattern, sample code (sanitized), expected detection behavior, and relevant MITRE ATT&CK technique ID

We will respond within 48 hours and work to release a patch. When the detection is implemented, it will be credited to the reporter (unless anonymity is requested).

### Extension Vulnerabilities

If you find a vulnerability in the extension code itself (e.g., path traversal in quarantine, rule injection via custom rules):

- Report via GitHub Security Advisories (link above)
- Include: proof of concept, affected component, severity assessment
- We will triage and respond within 24 hours for critical issues

### Handling of Malicious Samples

The `samples/` directory contains **simulated, safe** malware patterns:
- These files use harmless patterns (benign hex strings, safe eval calls, non-functional shell commands)
- They are designed to trigger detection rules without executing actual malicious actions
- If you add new sample files, ensure they follow this principle
- Never commit real malware, C2 beacons, or functional exploit code

### Third-Party Dependencies

This extension uses:
- `acorn` / `acorn-walk` — JavaScript parser (audited annually)
- `minimatch` — glob pattern matching (audited annually)
- `openai` — LLM client (audited before each major version)
- `@vscode/test-electron` — testing framework

We run `npm audit` before each release and address all high/critical vulnerabilities. Deps with only low-severity issues are tracked and resolved on the next minor release.

### Responsible Disclosure

We follow a 90-day responsible disclosure window:
1. **Day 0-1**: Acknowledge receipt of report
2. **Day 1-7**: Triage and reproduce the issue
3. **Day 7-30**: Develop and test a fix
4. **Day 30-45**: Release patched extension version
5. **Day 45-90**: Public disclosure (coordinated with reporter)

### Scope

**In scope:**
- Detection rules (false negatives, bypassable patterns)
- Extension source code (injection, path traversal, privilege escalation)
- Quarantine system (integrity bypass, unauthorized restore)
- Rule loading (injection via malicious JSON rules)
- npm audit engine (bypass with typosquatted packages)
- Interceptor bypass (tasks.json, npm scripts, git config)

**Out of scope:**
- Attacks on the underlying VS Code platform (report to Microsoft)
- Social engineering / phishing against maintainers
- Denial of service against test infrastructure
- Simulated sample files in `samples/` (these are intentionally detection-triggering)

### Sample Pattern Library

This project maintains a library of **safe, simulated** attack patterns for security research and testing. These patterns are used to validate detection rules and should never be interpreted as functional malware.

Contact: GitHub Security Advisory (preferred) or rulf-ra on GitHub.